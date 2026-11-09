#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""网页登录（手机号 / 验证码）拿 Trae 凭证，输出与导出脚本同格式的一行 JSON。

适用场景：不想从客户端 storage.json 里取登录态，改用浏览器登录。
前置条件：必须提供装过 Trae 客户端的机器上取到的真实设备号（12~20 位纯数字）。
          网页登录本身不会把设备号注册成可信设备，随便编一个号签到必然 9074。

用法：
    python tools/login.py --device-id 1234567890123
    python tools/login.py --device-id 1234567890123 --callback-url 'http://127.0.0.1:18080/authorize?...'
"""
from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib import trae_api  # noqa: E402

PORT = 18080
CALLBACK = "http://127.0.0.1:%d/authorize" % PORT
APP_VERSION = "0.1.43"
DEVICE_ID_RE = re.compile(r"^\d{12,20}$")


def build_login_url(device_id: str, port: int) -> str:
    callback = "http://127.0.0.1:%d/authorize" % port
    params = {
        "login_version": "1",
        "auth_from": "solo",
        "login_channel": "native_ide",
        "plugin_version": "2.3.62834",
        "auth_type": "local",
        "client_id": trae_api.CLIENT_ID,
        "redirect": "0",
        "login_trace_id": secrets.token_hex(8),
        "auth_callback_url": callback,
        "machine_id": device_id,
        "device_id": device_id,
        "x_device_id": device_id,
        "x_machine_id": device_id,
        "x_device_brand": "PC",
        "x_device_type": "PC",
        "x_os_version": "1.0",
        "x_app_version": APP_VERSION,
        "x_app_type": "stable",
    }
    return "https://www.trae.cn/authorization?" + urllib.parse.urlencode(params)


def parse_callback(url: str) -> dict:
    query = urllib.parse.urlparse(url).query
    return {k: v[0] for k, v in urllib.parse.parse_qs(query).items() if v}


def capture(port: int, timeout: int = 300) -> dict:
    """本地起一次性 HTTP 服务接回调；也支持手动粘贴回调链接。"""
    holder: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            holder.update(parse_callback(self.path))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write("登录信息已捕获，可以关掉这个页面了。".encode("utf-8"))

        def log_message(self, *_args):  # noqa: N802
            pass

    server = HTTPServer(("127.0.0.1", port), Handler)
    worker = threading.Thread(target=server.handle_request, daemon=True)
    worker.start()
    try:
        answer = input("浏览器若没自动跳回来，把地址栏完整链接粘贴到这里（直接回车则等待回调）: ").strip()
    except EOFError:
        answer = ""
    if answer.startswith("http"):
        holder.update(parse_callback(answer))
    else:
        worker.join(timeout)
    server.server_close()
    return holder


def _json_param(params: dict, key: str) -> dict:
    try:
        value = json.loads(urllib.parse.unquote(params.get(key, "") or "{}"))
        return value if isinstance(value, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def exchange(params: dict, device_id: str) -> dict:
    refresh = (params.get("refreshToken") or params.get("refresh_token")
               or params.get("data") or "")
    if not refresh:
        raise RuntimeError("回调里没有 refreshToken，参数：" + ", ".join(params.keys()))
    user_info = _json_param(params, "userInfo")
    user_jwt = _json_param(params, "userJwt")
    token = str(user_jwt.get("Token") or user_jwt.get("token") or user_jwt.get("AccessToken") or "")
    user_id = str(user_info.get("UserID") or user_jwt.get("UserID") or "")
    screen_name = str(user_info.get("ScreenName") or user_info.get("screenName") or "")
    bound_device = device_id
    expires_at = user_jwt.get("TokenExpireAt")

    if not token:
        body = json.dumps({
            "ClientID": trae_api.CLIENT_ID,
            "RefreshToken": refresh,
            "ClientSecret": "-",
            "UserID": user_id,
        })
        http, text = trae_api.post(trae_api.EP_EXCHANGE_LEGACY,
                                   {"Content-Type": "application/json",
                                    "Accept": "application/json",
                                    "User-Agent": trae_api.USER_AGENT}, body)
        if not (0 < http < 400):
            raise RuntimeError("ExchangeToken 失败 HTTP %s：%s" % (http, text[:200]))
        try:
            result = (json.loads(text).get("Result") or json.loads(text).get("data") or {})
        except json.JSONDecodeError as exc:
            raise RuntimeError("ExchangeToken 返回不是 JSON：" + text[:200]) from exc
        token = str(result.get("Token") or result.get("AccessToken") or "")
        refresh = str(result.get("RefreshToken") or refresh)
        bound_device = str(result.get("BoundDeviceID") or device_id)
        expires_at = result.get("TokenExpireAt") or expires_at
        if not token:
            raise RuntimeError("ExchangeToken 没返回 Token：" + text[:200])

    if not user_id:
        user_id = trae_api.decode_uid(token)
    exp = None
    try:
        if expires_at:
            value = float(expires_at)
            exp = value / 1000 if value > 1e12 else value
    except (TypeError, ValueError):
        pass

    return {
        "name": screen_name or user_id or "trae-account",
        "userId": user_id,
        "accessToken": token,
        "refreshToken": refresh,
        "expiresAt": exp,
        "deviceId": bound_device,
        "machineId": device_id,
        "devicePrivateKeyPem": "",
        "devicePublicKeyPem": "",
        "fingerprint": {"brand": "PC", "type": "Windows", "os": "10.0.19045"},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Trae 网页登录获取凭证")
    parser.add_argument("--device-id", default="", help="客户端真实设备号（12~20 位纯数字）")
    parser.add_argument("--callback-url", default="", help="已有回调链接时直接传入，跳过本地监听")
    parser.add_argument("--port", type=int, default=PORT, help="本地回调端口，默认 18080")
    args = parser.parse_args()

    device_id = args.device_id.strip() or input("请输入客户端真实设备号（12~20 位纯数字）: ").strip()
    if not DEVICE_ID_RE.fullmatch(device_id):
        print("设备号格式不对。必须是客户端注册过的 12~20 位纯数字，"
              "见 storage.json 里的 iCubeAuthInfo://icube-dc:<数字>。", file=sys.stderr)
        return 1

    if args.callback_url:
        params = parse_callback(args.callback_url)
    else:
        print("\n请在浏览器打开下面链接，用手机号 / 验证码登录：\n", file=sys.stderr)
        print(build_login_url(device_id, args.port) + "\n", file=sys.stderr)
        params = capture(args.port)

    if not params:
        print("没有拿到回调参数。可以用 --callback-url 直接粘贴浏览器地址栏的完整链接。", file=sys.stderr)
        return 1
    try:
        account = exchange(params, device_id)
    except RuntimeError as exc:
        print("登录失败：%s" % exc, file=sys.stderr)
        return 1

    print("\n" + "=" * 72, file=sys.stderr)
    print("登录成功。网页登录拿不到设备私钥，新版续期可能报 20405；", file=sys.stderr)
    print("如需长期无人值守，优先用 tools/export_credentials.py 导出完整登录态。", file=sys.stderr)
    print("把下面这一整行复制进 GitHub Secret：TRAE_ACCOUNTS", file=sys.stderr)
    print("=" * 72 + "\n", file=sys.stderr)
    print(json.dumps([account], ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
