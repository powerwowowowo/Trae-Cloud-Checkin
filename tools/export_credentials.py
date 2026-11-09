#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本机导出 Trae 客户端登录态 → 一行 JSON，粘贴进 GitHub Secret TRAE_ACCOUNTS。

用法（在装了 Trae CN / TRAE SOLO CN 且已登录的机器上，Python 3.10+，零依赖）：
    python tools/export_credentials.py

只读本地 storage.json，不联网、不修改客户端文件、默认不落盘。
输出的这一行 JSON 含 accessToken / refreshToken / 设备私钥，等同于账号密码，
只放进 GitHub Secrets，千万别提交进仓库或发给别人。
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib import crypto, trae_api  # noqa: E402

APP_DIRS = ("Trae CN", "TRAE SOLO CN", "TRAE SOLO", "Trae", "TraeWork", "TraeWork CN")
AUTH_KEY = "iCubeAuthInfo://icube.cloudide"
DC_PREFIX = "iCubeAuthInfo://icube-dc:"
DEVICE_ID_RE = re.compile(r"^\d{12,20}$")


def candidate_paths() -> list[Path]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA") or (home / "AppData" / "Roaming"))
    bases = [appdata, home / "Library" / "Application Support", home / ".config", home]
    found: list[Path] = []
    for base in bases:
        for name in APP_DIRS:
            for suffix in (("User", "globalStorage", "storage.json"), ("storage.json",)):
                path = base.joinpath(name, *suffix)
                if path.is_file() and path not in found:
                    found.append(path)
    return found


def find_device(storage: dict) -> tuple[str, dict]:
    """从 storage.json 里找客户端真实注册的设备号与设备密钥。"""
    device_id, payload = "", None
    for key, value in storage.items():
        if key.startswith(DC_PREFIX):
            candidate = key[len(DC_PREFIX):].strip()
            if DEVICE_ID_RE.fullmatch(candidate):
                device_id, payload = candidate, value
                break
        elif key.rstrip(":") == "iCubeAuthInfo://icube-dc" and DEVICE_ID_RE.fullmatch(str(value).strip()):
            device_id = str(value).strip()
    device: dict = {}
    if payload:
        try:
            device = crypto.tc_decrypt(payload)
        except crypto.CryptoError as exc:
            print("[!] 设备密钥解密失败：%s" % exc, file=sys.stderr)
    return device_id, device


def extract(path: Path, brand: str = "") -> dict:
    storage = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(storage, dict):
        raise ValueError("storage.json 根节点不是对象")

    auth: dict = {}
    if storage.get(AUTH_KEY):
        auth = crypto.tc_decrypt(storage[AUTH_KEY])
    if not auth:
        raise ValueError("未找到 %s（客户端可能未登录）" % AUTH_KEY)

    device_id, device = find_device(storage)
    token = str(auth.get("token") or auth.get("accessToken") or auth.get("AccessToken") or "")
    refresh = str(auth.get("refreshToken") or auth.get("RefreshToken") or "")
    if not token and not refresh:
        raise ValueError("凭据里既没有 token 也没有 refreshToken")

    return {
        "name": str(auth.get("username") or auth.get("screenName") or auth.get("screen_name") or "trae-account"),
        "userId": str(auth.get("userId") or auth.get("uid") or trae_api.decode_uid(token)),
        "accessToken": token,
        "refreshToken": refresh,
        "expiresAt": auth.get("expiresAt") or None,
        "deviceId": device_id,
        "machineId": str(storage.get("telemetry.machineId") or storage.get("machineId") or device_id),
        "devicePrivateKeyPem": str(device.get("privateKeyPEM") or device.get("privateKeyPem")
                                   or device.get("privateKey") or ""),
        "devicePublicKeyPem": str(device.get("publicKeyPEM") or device.get("publicKeyPem")
                                  or device.get("publicKey") or ""),
        "fingerprint": {
            "brand": brand or str(device.get("brand") or ""),
            "type": platform.system() or "Windows",
            "os": platform.version() or "10.0.19045",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="导出 Trae 客户端登录态")
    parser.add_argument("--storage", default="", help="手动指定 storage.json 路径")
    parser.add_argument("--brand", default="", help="覆盖 x-device-brand（一般留空）")
    parser.add_argument("--output", default="", help="可选：把 JSON 写入本地文件（默认只打印）")
    args = parser.parse_args()

    paths = [Path(args.storage)] if args.storage else candidate_paths()
    if not paths:
        print("未找到 Trae 客户端 storage.json。请用 --storage 指定路径。", file=sys.stderr)
        print("常见位置：%APPDATA%\\Trae CN\\User\\globalStorage\\storage.json", file=sys.stderr)
        return 1

    accounts, errors = [], []
    for path in paths:
        if not path.is_file():
            continue
        try:
            accounts.append(extract(path, args.brand))
            print("[+] 解析成功：%s" % path, file=sys.stderr)
        except Exception as exc:
            errors.append("%s → %s" % (path, exc))
            print("[!] %s → %s" % (path, exc), file=sys.stderr)

    if not accounts:
        print("没有任何可用凭据。", file=sys.stderr)
        return 1

    warnings = []
    for acc in accounts:
        if not DEVICE_ID_RE.fullmatch(acc["deviceId"] or ""):
            warnings.append("账号 %s 没取到真实设备号（12~20 位纯数字），云端签到必然返回 9074" % acc["name"])
        if not acc["devicePrivateKeyPem"]:
            warnings.append("账号 %s 没取到设备私钥，新版 token 续期可能返回 20405（会尝试旧端点兜底）" % acc["name"])
        if not acc["refreshToken"]:
            warnings.append("账号 %s 没有 refreshToken，token 过期后无法自动续期" % acc["name"])
    for line in warnings:
        print("[!] " + line, file=sys.stderr)

    line = json.dumps(accounts, ensure_ascii=False, separators=(",", ":"))
    print("\n" + "=" * 72, file=sys.stderr)
    print("把下面这一整行复制进 GitHub Secret：TRAE_ACCOUNTS", file=sys.stderr)
    print("再随机生成一个 STATE_KEY：python -c \"import secrets;print(secrets.token_urlsafe(32))\"", file=sys.stderr)
    print("=" * 72 + "\n", file=sys.stderr)
    print(line)
    if args.output:
        Path(args.output).write_text(line, encoding="utf-8")
        print("[+] 已写入 %s（用完请删除）" % args.output, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
