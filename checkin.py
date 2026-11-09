#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Trae CN 云端每日签到主程序（GitHub Actions 中无人值守运行）。

流程：加载凭证 → token 续期 → 查状态 → 领积分 → 回查到账 → 加密保存新 token
      → 输出汇总 / GitHub Step Summary / 可选通知。

安全约束：全程不打印任何 token、refreshToken 或设备私钥。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib import crypto, state, trae_api  # noqa: E402

RESULT_FILE = ROOT / "result.json"
OK_STATES = ("OK", "ALREADY", "DRY_RUN", "DISABLED")
BAD_STATES = ("UNCONFIRMED", "RATE_LIMITED", "TOKEN_EXPIRED", "FAILED")

LABELS = {
    "OK": "签到成功",
    "ALREADY": "今日已签",
    "DRY_RUN": "仅查询",
    "DISABLED": "活动未开启",
    "UNCONFIRMED": "成功但积分未到账",
    "RATE_LIMITED": "9074 设备/限流，本轮不重试",
    "TOKEN_EXPIRED": "登录态失效，需重新导出凭证",
    "FAILED": "失败",
}


def log(message: str) -> None:
    print("[%s] %s" % (time.strftime("%H:%M:%S"), message), flush=True)


def _short(value: str) -> str:
    value = str(value or "")
    return value[:4] + "…" + value[-4:] if len(value) > 10 else value


def _mask_uid(value: str) -> str:
    """公开仓库的日志与 result.json artifact 任何人可见，账号 ID 只留尾号。

    内部账号字典仍保留完整 userId（状态文件按 userId+deviceId 匹配），
    这里只处理对外输出。
    """
    value = str(value or "")
    return "***" + value[-4:] if len(value) > 4 else ("***" if value else "")


def run_account(account: dict, dry_run: bool = False, verify: bool = True) -> dict:
    """处理单个账号，返回结果字典（不含任何凭据字段）。"""
    name = account.get("name") or "trae-account"
    result = {
        "name": name,
        "userId": _mask_uid(account.get("userId")),
        "deviceIdTail": str(account.get("deviceId") or "")[-4:],
        "state": "FAILED",
        "label": "",
        "code": None,
        "points": None,
        "credits": 0,
        "refreshed": False,
        "message": "",
    }

    # 1. accessToken 快过期就先续期，同时接住轮换后的 refreshToken
    if trae_api.needs_refresh(account):
        if account.get("refreshToken"):
            ok, note = trae_api.refresh_account(account)
            result["refreshed"] = ok
            if not ok:
                log("%s 续期失败：%s" % (name, note))
                if not account.get("accessToken"):
                    result.update(state="TOKEN_EXPIRED", message=note)
                    return _finish(result)
        elif not account.get("accessToken"):
            result.update(state="TOKEN_EXPIRED", message="无 token 且无 refreshToken")
            return _finish(result)

    # 2. 查询签到状态（鉴权失效就续期后重试一次）
    status = trae_api.status_of(account)
    code = status.get("code", -1)
    if code in trae_api.AUTH_FAIL_CODES and account.get("refreshToken"):
        ok, note = trae_api.refresh_account(account)
        result["refreshed"] = ok
        if ok:
            status = trae_api.status_of(account)
            code = status.get("code", -1)

    if status.get("_http", -1) >= 400 or code in (None, -1):
        result.update(state="FAILED", code=code,
                      message="查询状态失败 HTTP %s：%s" % (status.get("_http"),
                                                        str(status.get("message") or status.get("raw") or "")[:160]))
        return _finish(result)
    if code != 0:
        result.update(state="FAILED", code=code,
                      message="查询状态返回 code=%s %s" % (code, status.get("message") or ""))
        return _finish(result)

    result["credits"] = trae_api.credits_of(status)
    if status.get("enable") is False:
        result.update(state="DISABLED", code=code, message="服务端返回签到活动未开启")
        return _finish(result)
    if status.get("checked_in"):
        result.update(state="ALREADY", code=code, message="今日已签到，无需重复领取")
        return _finish(result)
    if dry_run:
        result.update(state="DRY_RUN", code=code, message="今日未签到（dry-run 未领取）")
        return _finish(result)

    # 3. 领取积分。9074 不做当场重试：实测连发会延长惩罚窗口，次日自动重来
    claimed = trae_api.claim(account)
    code = claimed.get("code", -1)
    http = claimed.get("_http", -1)
    message = str(claimed.get("message") or claimed.get("raw") or "")[:160]
    if code in trae_api.AUTH_FAIL_CODES and account.get("refreshToken"):
        ok, _ = trae_api.refresh_account(account)
        result["refreshed"] = ok
        if ok:
            claimed = trae_api.claim(account)
            code, http = claimed.get("code", -1), claimed.get("_http", -1)
            message = str(claimed.get("message") or "")[:160]

    payload = claimed.get("data")
    if isinstance(payload, dict):
        result["points"] = payload.get("points")
    if code == 0:
        if verify:
            confirm = trae_api.status_of(account)
            if not confirm.get("checked_in"):
                result.update(state="UNCONFIRMED", code=0,
                              message="接口返回成功，但回查未见今日签到记录")
                return _finish(result)
            result["credits"] = trae_api.credits_of(confirm) or result["credits"]
        result.update(state="OK", code=0, message="积分已到账" if verify else "接口返回成功")
        return _finish(result)
    if code in trae_api.ALREADY_CODES:
        # 9095 是「设备今日已签到」，9004 可能是参数错误；带上服务端原文，别把两者混为一谈
        result.update(state="ALREADY", code=code,
                      message="今日已签（code=%s）%s" % (code, message))
        return _finish(result)
    if code == trae_api.RATE_CODE or http in trae_api.RATE_HTTP_CODES:
        result.update(state="RATE_LIMITED", code=code,
                      message="code=%s HTTP=%s，本轮不重试，次日自动重来（急用可手动 Run workflow）；"
                              "若持续出现请检查设备号是否为客户端真实注册值" % (code, http))
        return _finish(result)
    result.update(state="FAILED", code=code, message=message or "未知错误")
    return _finish(result)


def _finish(result: dict) -> dict:
    result["label"] = LABELS.get(result["state"], result["state"])
    return result


def write_outputs(results: list[dict], started: float, note: str) -> dict:
    counts = {k: sum(1 for r in results if r["state"] == k) for k in LABELS}
    summary = {
        "generatedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "durationSeconds": round(time.time() - started, 1),
        "source": note,
        "counts": counts,
        "results": results,
        "success": all(r["state"] in OK_STATES for r in results),
    }
    RESULT_FILE.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "## Trae 每日签到结果", "",
        "| 账号 | 状态 | 本次积分 | 总积分 | 说明 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in results:
        lines.append("| %s | %s | %s | %s | %s |" % (
            r["name"], r["label"],
            r["points"] if r["points"] is not None else "-",
            r["credits"] or "-",
            str(r["message"]).replace("|", "/")[:120],
        ))
    lines += ["", "统计：" + " / ".join("%s %d" % (LABELS[k], v) for k, v in counts.items() if v), ""]
    text = "\n".join(lines)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        try:
            with open(step_summary, "a", encoding="utf-8") as fh:
                fh.write(text)
        except OSError:
            pass
    return summary


def notify(summary: dict) -> None:
    """可选通知：企业微信机器人 / Bark / PushPlus。任一失败都不影响签到结果。"""
    counts = summary["counts"]
    parts = ["%s %d" % (LABELS[k], v) for k, v in counts.items() if v]
    title = "Trae 签到完成" if summary["success"] else "Trae 签到有异常"
    body = " / ".join(parts) or "无账号"
    for r in summary["results"]:
        body += "\n%s: %s %s" % (r["name"], r["label"], r["message"][:60])
    headers = {"Content-Type": "application/json"}

    def post(url: str, payload: dict) -> None:
        req = urllib.request.Request(url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                     headers=headers, method="POST")
        urllib.request.urlopen(req, timeout=10).close()

    webhook = os.environ.get("NOTIFY_WEBHOOK", "").strip()
    bark = os.environ.get("BARK_URL", "").strip()
    pushplus = os.environ.get("PUSHPLUS_TOKEN", "").strip()
    try:
        if webhook:
            post(webhook, {"msgtype": "text", "text": {"content": title + "\n" + body}})
            log("通知已发送（企业微信 / webhook）")
        if bark:
            url = "%s/%s/%s" % (bark.rstrip("/"), urllib.parse.quote(title), urllib.parse.quote(body))
            urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=10).close()
            log("通知已发送（Bark）")
        if pushplus:
            post("https://www.pushplus.plus/send",
                 {"token": pushplus, "title": title, "content": body.replace("\n", "<br>"), "template": "html"})
            log("通知已发送（PushPlus）")
    except Exception as exc:
        log("通知发送失败（不影响签到）：%s" % type(exc).__name__)


def main() -> int:
    parser = argparse.ArgumentParser(description="Trae CN 云端每日签到")
    parser.add_argument("--dry-run", action="store_true", help="只查询状态，不领取积分、不续期")
    parser.add_argument("--no-verify", action="store_true", help="跳过签到后的到账回查")
    parser.add_argument("--no-save", action="store_true", help="不写回加密状态文件")
    parser.add_argument("--accounts", default=None, help="本地调试用：JSON 字符串或 JSON 文件路径")
    args = parser.parse_args()

    started = time.time()
    secret = args.accounts
    if secret and not secret.strip().startswith(("[", "{")):
        path = Path(secret)
        if path.is_file():
            secret = path.read_text(encoding="utf-8")
    try:
        accounts, note = state.load_accounts(secret)
    except (state.ConfigError, crypto.CryptoError) as exc:
        log("配置错误：%s" % exc)
        return 2

    log("已加载 %d 个账号，来源：%s" % (len(accounts), note))
    if not os.environ.get("STATE_KEY") and not args.no_save:
        log("警告：未设置 STATE_KEY，轮换后的 refreshToken 无法持久化，几天后登录态会失效")

    results = []
    for index, account in enumerate(accounts, 1):
        log("(%d/%d) %s 设备尾号 %s 开始" % (index, len(accounts), account["name"],
                                          str(account.get("deviceId") or "")[-4:]))
        try:
            result = run_account(account, dry_run=args.dry_run, verify=not args.no_verify)
        except Exception as exc:  # 单账号异常不能拖垮整轮
            result = _finish({"name": account["name"], "userId": _mask_uid(account.get("userId", "")),
                              "deviceIdTail": str(account.get("deviceId") or "")[-4:],
                              "state": "FAILED", "code": None, "points": None, "credits": 0,
                              "refreshed": False,
                              "message": "%s: %s" % (type(exc).__name__, str(exc)[:120])})
        results.append(result)
        log("  → %s | %s" % (result["label"], result["message"][:120]))
        if index < len(accounts):
            time.sleep(3)

    if not args.dry_run and not args.no_save and os.environ.get("STATE_KEY"):
        try:
            saved = state.save_accounts(accounts)
            try:
                display = str(saved.relative_to(ROOT))
            except ValueError:
                display = str(saved)
            log("加密状态已写入 %s" % display)
        except (crypto.CryptoError, OSError) as exc:
            log("状态写入失败：%s（下次运行将用旧 refreshToken，请检查 STATE_KEY）" % exc)

    summary = write_outputs(results, started, note)
    log("汇总：" + " / ".join("%s %d" % (LABELS[k], v) for k, v in summary["counts"].items() if v))
    notify(summary)
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
