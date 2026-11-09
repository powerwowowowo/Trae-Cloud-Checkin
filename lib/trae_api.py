#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Trae CN 签到接口客户端（纯标准库 HTTP，零第三方依赖）。

对齐桌面端 Trae CN 1.107.1 的请求特征：
  * Authorization: Cloud-IDE-JWT <token>
  * 只发小写 x-device-id，必须是客户端真实注册过的纯数字设备号
  * 请求体固定 {"req_source": 1}（空体会被风控拒成 9074）
  * 新版 token 续期需要 ECDSA P-256 设备证明（DeviceProof + DeviceInfo）

业务码：0 成功 / 9004、9095 今日已签 / 9074 设备指纹或限流 / 1001、1002 鉴权失效
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from . import crypto

UG_HOST = "https://api.trae.cn"
OAUTH_HOST = "https://api.trae.com.cn"

CLIENT_ID = "en1oxy7wnw8j9n"          # SOLO / 旧客户端
CLIENT_ID_IDE = "ono9krqynydwx5"      # Trae CN 桌面端（新版续期）
IDE_VERSION = "1.107.1"
USER_AGENT = "Trae/" + IDE_VERSION

EP_STATUS = UG_HOST + "/trae/api/v2/ug/checkin_credits/status"
EP_CLAIM = UG_HOST + "/trae/api/v2/ug/checkin_credits/claim"
EP_EXCHANGE_PROOF = UG_HOST + "/trae/api/v3/oauth/ExchangeToken"
EP_EXCHANGE_LEGACY = OAUTH_HOST + "/cloudide/api/v3/trae/oauth/ExchangeToken"
PROOF_PATH = "/trae/api/v3/oauth/ExchangeToken"

REQ_BODY = '{"req_source": 1}'

CODE_OK = 0
ALREADY_CODES = (9004, 9095)
RATE_CODE = 9074
AUTH_FAIL_CODES = (1001, 1002, 401, 403)
RATE_HTTP_CODES = (429, 500, 502, 503, 504)
REFRESH_MARGIN = 600  # token 剩余不足 10 分钟就先续期


RETRY_HTTP_CODES = (429, 500, 502, 503, 504)


def post(url: str, headers: dict, body: str, timeout: int = 25, retries: int = 2) -> tuple[int, str]:
    """返回 (http_status, response_text)。网络错误与服务端临时故障有限退避重试，不抛异常。

    HTTP 200 里带 9074 这类业务限流码不会在这里重试——连发会延长惩罚窗口，
    由上层按业务码处理。一天只跑一轮定时，容错全部收在这一层。
    """
    data = body.encode("utf-8") if isinstance(body, str) else body
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace")
            if exc.code in RETRY_HTTP_CODES and attempt < retries:
                time.sleep(2 ** attempt)
                continue
            return exc.code, text
        except Exception as exc:
            if attempt >= retries:
                return -1, str(exc)
            time.sleep(2 ** attempt)
    return -1, "unreachable"


def ug_headers(account: dict) -> dict:
    """构造与桌面端一致的 ug 设备头。"""
    fp = account.get("fingerprint") or {}
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Cloud-IDE-JWT " + str(account.get("accessToken") or ""),
        "X-User-Region": "CN",
        "User-Agent": USER_AGENT,
        "x-app-version": IDE_VERSION,
        "x-device-type": str(fp.get("type") or "Windows"),
        "x-os-version": str(fp.get("os") or "10.0.19045"),
    }
    device_id = str(account.get("deviceId") or "").strip()
    if device_id:
        # 只发小写：同时发大小写两个头会被服务端判为异常客户端
        headers["x-device-id"] = device_id
    brand = str(fp.get("brand") or "").strip()
    if brand:
        headers["x-device-brand"] = brand
    return headers


def _decode(text: str) -> dict:
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {"raw": text}
    except json.JSONDecodeError:
        return {"raw": text[:200]}


def status_of(account: dict) -> dict:
    """查询签到状态。返回接口 JSON（含 code / checked_in / credits / enable）。"""
    http, text = post(EP_STATUS, ug_headers(account), REQ_BODY)
    result = _decode(text)
    result["_http"] = http
    return result


def claim(account: dict) -> dict:
    """领取每日积分。返回接口 JSON（成功时 data.points 为本次积分）。"""
    http, text = post(EP_CLAIM, ug_headers(account), REQ_BODY)
    result = _decode(text)
    result["_http"] = http
    return result


def decode_uid(token: str) -> str:
    """从 Cloud-IDE-JWT 的 payload.data.id 提取用户 ID；拿不到返回空串。"""
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(part))
        data = payload.get("data") or {}
        return str(data.get("id") or payload.get("UserID") or payload.get("uid") or "")
    except Exception:
        return ""


def needs_refresh(account: dict) -> bool:
    exp = account.get("expiresAt")
    if not exp:
        return True
    try:
        return float(exp) - time.time() < REFRESH_MARGIN
    except (TypeError, ValueError):
        return True


def _device_info(account: dict, platform_code: str) -> dict:
    fp = account.get("fingerprint") or {}
    device_id = str(account.get("deviceId") or "")
    return {
        "DeviceID": device_id,
        "MachineID": str(account.get("machineId") or device_id),
        "PlatformCode": platform_code,
        "DeviceType": "PC",
        "DeviceName": str(account.get("deviceName") or "PC"),
        "DeviceModel": str(account.get("deviceModel") or ""),
        "ClientVersion": IDE_VERSION,
        "DevicePublicKey": crypto.norm_pem(str(account.get("devicePublicKeyPem") or "")),
        "DeviceBrand": str(fp.get("brand") or ""),
        "DeviceCPU": "",
        "OSInfo": str(fp.get("type") or "Windows"),
        "OSVersion": str(fp.get("os") or ""),
    }


def _parse_exchange(text: str, old_refresh: str) -> tuple[str, str, float | None]:
    result = _decode(text).get("Result") or _decode(text).get("data") or {}
    if not isinstance(result, dict):
        result = {}
    token = (result.get("Token") or result.get("AccessToken")
             or result.get("access_token") or result.get("token") or "")
    refresh = (result.get("RefreshToken") or result.get("refresh_token")
               or result.get("refreshToken") or old_refresh)
    exp = result.get("TokenExpireAt") or result.get("expiresAt")
    expires_at = None
    try:
        if exp:
            value = float(exp)
            expires_at = value / 1000 if value > 1e12 else value
    except (TypeError, ValueError):
        pass
    return str(token), str(refresh), expires_at


def refresh_account(account: dict) -> tuple[bool, str]:
    """续期 accessToken，并原地更新账号（含轮换后的 refreshToken）。

    优先走带设备证明的新端点，失败按 ClientID × 产品线组合回退，最后退旧端点。
    """
    old_refresh = str(account.get("refreshToken") or "")
    if not old_refresh:
        return False, "缺少 refreshToken"

    priv = str(account.get("devicePrivateKeyPem") or "")
    pub = str(account.get("devicePublicKeyPem") or "")
    attempts: list[tuple[int, str]] = []

    if priv and pub and account.get("deviceId"):
        combos = [(CLIENT_ID_IDE, "IDE_PC"), (CLIENT_ID, "IDE_PC"), (CLIENT_ID, "SOLO_PC")]
        for client_id, platform_code in combos:
            ts = int(time.time())
            nonce = os.urandom(16).hex()
            canonical = "\n".join(["POST", PROOF_PATH, client_id, old_refresh, str(ts), nonce])
            try:
                signature = crypto.sign_p256(priv, canonical.encode("utf-8"))
            except crypto.CryptoError as exc:
                return False, "设备签名失败：" + str(exc)
            proof = {"Timestamp": ts, "Nonce": nonce, "Signature": signature}
            body = json.dumps({
                "ClientID": client_id,
                "ClientSecret": "",
                "RefreshToken": old_refresh,
                "DeviceInfo": _device_info(account, platform_code),
                "DeviceProof": proof,
                "IDEVersion": IDE_VERSION,
            }, ensure_ascii=False)
            http, text = post(EP_EXCHANGE_PROOF,
                              {"Content-Type": "application/json", "x-cloudide-token": ""},
                              body)
            attempts.append((http, text[:160]))
            if 0 < http < 400:
                token, refresh, exp = _parse_exchange(text, old_refresh)
                if token:
                    _apply(account, token, refresh, exp)
                    return True, "新端点续期成功"
            # 只有「钥匙 / 产品线不匹配」才值得换组合重试
            if "10101" not in text and "20403" not in text:
                break

    body = json.dumps({
        "ClientID": CLIENT_ID,
        "RefreshToken": old_refresh,
        "ClientSecret": "-",
        "UserID": str(account.get("userId") or ""),
    })
    http, text = post(EP_EXCHANGE_LEGACY, {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }, body)
    attempts.append((http, text[:160]))
    if 0 < http < 400:
        token, refresh, exp = _parse_exchange(text, old_refresh)
        if token:
            _apply(account, token, refresh, exp)
            return True, "旧端点续期成功"
    return False, "续期失败：" + "; ".join("HTTP %s %s" % a for a in attempts[-2:])


def _apply(account: dict, token: str, refresh: str, exp: float | None) -> None:
    account["accessToken"] = token
    account["refreshToken"] = refresh
    account["expiresAt"] = exp if exp else time.time() + 3600
    if not account.get("userId"):
        account["userId"] = decode_uid(token)


def credits_of(status: dict) -> int:
    """尽量取出接口返回的总积分，用于日志展示。"""
    for key in ("credits", "total_credits", "totalCredits"):
        value = status.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return int(value)
    data = status.get("data")
    if isinstance(data, dict):
        for key in ("credits", "total", "balance"):
            value = data.get(key)
            if isinstance(value, (int, float)):
                return int(value)
    return 0
