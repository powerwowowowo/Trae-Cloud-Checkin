#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""账号凭证加载与轮换状态持久化。

设计要点：
  * 账号按 TRAE_ACCOUNTS、TRAE_ACCOUNTS_2 ... TRAE_ACCOUNTS_9 顺序合并。
    GitHub Secret 只能写不能读，编号式新增账号无需读取或覆盖已有 Secret；
  * state/credentials.enc 只覆盖 accessToken / refreshToken / expiresAt，
    因为 Trae 每次续期都会轮换 refreshToken，静态 Secret 会越刷越失效；
  * 状态文件用 STATE_KEY 派生的 AES-128-CBC + HMAC-SHA256 密钥加密后才提交回私有仓库，
    即使仓库内容外泄，没有 STATE_KEY 也解不出 token。
"""
from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any

from . import crypto

ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = ROOT / "state" / "credentials.enc"
TOKEN_FIELDS = ("accessToken", "refreshToken", "expiresAt")
# 每个 Secret 放一个（或一组）账号；加号时只需新增下一个编号，永远不用覆盖旧的。
ACCOUNT_SECRET_NAMES = ("TRAE_ACCOUNTS",) + tuple("TRAE_ACCOUNTS_%d" % i for i in range(2, 10))


class ConfigError(Exception):
    """配置缺失或格式错误。"""


def _first(account: dict, *keys: str) -> str:
    for key in keys:
        value = account.get(key)
        if value:
            return str(value)
    return ""


def _jwt_exp(token: str) -> float | None:
    """从 Cloud-IDE-JWT 的 payload.exp 取过期时间（秒）。

    Trae 客户端的 storage.json 不存 expiresAt，缺了它 needs_refresh() 会每轮都续期；
    而本机客户端也在轮换 refreshToken，云端拿旧值续期必然 10101。
    """
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(part))
        exp = payload.get("exp")
        if exp is None:
            return None
        exp = float(exp)
        return exp / 1000 if exp > 1e12 else exp
    except (IndexError, ValueError, TypeError, json.JSONDecodeError):
        return None


def normalize(raw: dict) -> dict:
    """统一字段名，兼容几个常见开源项目的凭证格式。"""
    fp = raw.get("fingerprint") or {}
    if not isinstance(fp, dict):
        fp = {}
    account = {
        "name": _first(raw, "name", "nickname", "screenName", "display") or "trae-account",
        "userId": _first(raw, "userId", "uid", "UserID"),
        "accessToken": _first(raw, "accessToken", "token", "Token", "AccessToken"),
        "refreshToken": _first(raw, "refreshToken", "RefreshToken", "refresh_token"),
        "expiresAt": raw.get("expiresAt") or raw.get("TokenExpireAt") or None,
        "deviceId": _first(raw, "deviceId", "claimDeviceId", "DeviceID", "device_id"),
        "machineId": _first(raw, "machineId", "MachineID"),
        "devicePrivateKeyPem": _first(raw, "devicePrivateKeyPem", "deviceKeyPem",
                                      "privateKeyPEM", "privateKeyPem"),
        "devicePublicKeyPem": _first(raw, "devicePublicKeyPem", "devicePubPem",
                                     "publicKeyPEM", "publicKeyPem"),
        "deviceName": _first(raw, "deviceName", "DeviceName") or "PC",
        "deviceModel": _first(raw, "deviceModel", "DeviceModel"),
        "fingerprint": {
            "brand": _first(fp, "brand", "Brand") or "",
            "type": _first(fp, "type", "Type") or "Windows",
            "os": _first(fp, "os", "OS") or "10.0.19045",
        },
    }
    if account["expiresAt"]:
        try:
            value = float(account["expiresAt"])
            account["expiresAt"] = value / 1000 if value > 1e12 else value
        except (TypeError, ValueError):
            account["expiresAt"] = _jwt_exp(account["accessToken"])
    else:
        account["expiresAt"] = _jwt_exp(account["accessToken"])
    return account


def _identity(account: dict) -> tuple[str, str]:
    return (account.get("userId") or "", account.get("deviceId") or "")


def _derive_device_id(base: str, used: set[str]) -> str:
    """同设备号被多个账号复用时，给后者派生一个不同的纯数字号。

    Trae 签到按 x-device-id 做「设备今日已签到」(code 9095) 幂等，
    同一客户端切号导出的多个账号会共用设备号，后者永远领不到积分。
    实测签到接口接受「同格式但不同值」的纯数字号，且不带设备头会返回 9004 参数错误，
    所以必须派生而不是留空。派生是确定性的，状态文件按 userId + deviceId 匹配不会错乱。
    """
    if not base.isdigit() or not (12 <= len(base) <= 20):
        return base
    for tail in "0123456789":
        cand = base[:-1] + tail
        if cand != base and cand not in used:
            return cand
    for second in "0123456789":
        for tail in "0123456789":
            cand = base[:-2] + second + tail
            if cand != base and cand not in used:
                return cand
    return base


def _parse_secret(name: str, raw: str) -> list[dict]:
    """解析单个 Secret 的 JSON，返回其中的账号对象。"""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError("Secret %s 不是合法 JSON：%s" % (name, exc)) from exc
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list) or not parsed:
        raise ConfigError("Secret %s 必须是非空 JSON 数组（或单个对象）" % name)
    return [item for item in parsed if isinstance(item, dict)]


def load_accounts(secret_value: str | None = None) -> tuple[list[dict], str]:
    """返回 (账号列表, 状态来源说明)。

    生产环境按 TRAE_ACCOUNTS、TRAE_ACCOUNTS_2 ... TRAE_ACCOUNTS_9 顺序合并。
    显式传入 secret_value 时只解析该值（本地 --accounts 调试与单元测试用）。
    """
    if secret_value is not None:
        sources = [("TRAE_ACCOUNTS", secret_value)]
    else:
        sources = [(name, os.environ.get(name, "")) for name in ACCOUNT_SECRET_NAMES]

    items: list[dict] = []
    used: list[str] = []
    for name, raw in sources:
        text = (raw or "").strip()
        if not text:
            continue
        items.extend(_parse_secret(name, text))
        used.append(name)
    if not items:
        raise ConfigError("缺少账号 Secret %s（本机运行 tools/export_credentials.py 生成）"
                          % ACCOUNT_SECRET_NAMES[0])

    accounts: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        acc = normalize(item)
        key = _identity(acc)
        if key in seen:
            continue
        seen.add(key)
        accounts.append(acc)
    if not accounts:
        raise ConfigError("账号 Secret 里没有有效账号对象")
    for acc in accounts:
        if not acc["refreshToken"] and not acc["accessToken"]:
            raise ConfigError("账号 %s 既没有 accessToken 也没有 refreshToken" % acc["name"])
        if not acc["deviceId"]:
            raise ConfigError("账号 %s 缺少 deviceId（真实设备号，否则必然 9074）" % acc["name"])

    # 同一客户端切号导出的多个账号会共用 deviceId；不改会让后者被 9095 挡住。
    used_devices: set[str] = set()
    derived: list[str] = []
    for acc in accounts:
        did = str(acc["deviceId"] or "")
        if did in used_devices:
            new = _derive_device_id(did, used_devices)
            if new != did:
                acc["deviceId"] = new
                derived.append("%s→%s" % (did[-4:], new[-4:]))
            did = new
        used_devices.add(did)

    note = "Secret " + " + ".join(used)
    if derived:
        note += "（设备号冲突，已自动派生 %s）" % ", ".join(derived)
    if STATE_FILE.is_file():
        try:
            cached = crypto.decrypt_state(STATE_FILE.read_bytes())
            items = cached.get("accounts") if isinstance(cached, dict) else None
            if isinstance(items, list):
                index = {_identity(normalize(x)): normalize(x) for x in items if isinstance(x, dict)}
                merged = 0
                for acc in accounts:
                    old = index.get(_identity(acc))
                    if not old:
                        continue
                    for field in TOKEN_FIELDS:
                        if old.get(field) and old.get(field) != acc.get(field):
                            acc[field] = old[field]
                            merged += 1
                note += " + 加密状态文件（%d 个字段沿用上次轮换结果）" % merged
        except crypto.CryptoError as exc:
            note += "；状态文件不可用（%s），已回退 Secret" % exc
    return accounts, note


def save_accounts(accounts: list[dict]) -> Path:
    """把最新凭证加密写入 state/credentials.enc。"""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "updatedAt": int(time.time()),
        "accounts": [{k: v for k, v in acc.items() if k != "_result"} for acc in accounts],
    }
    blob = crypto.encrypt_state(payload)
    tmp = STATE_FILE.with_suffix(".enc.tmp")
    tmp.write_bytes(blob)
    tmp.replace(STATE_FILE)
    return STATE_FILE


def mask(token: str) -> str:
    """日志里展示 token 时的遮罩形式。"""
    if not token:
        return "<empty>"
    return token[:4] + "…" + token[-4:] if len(token) > 12 else "***"
