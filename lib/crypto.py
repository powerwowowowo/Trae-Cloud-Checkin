#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""凭据解密 / 状态加密 / 设备签名 —— 纯 Python 标准库，零第三方依赖。

  1. tc_decrypt      解密 Trae 桌面端 storage.json 里的 iCubeAuthInfo 值
  2. encrypt_state   把轮换后的 token 状态加密成可提交进私有仓库的字节串
                     格式：TCC1 | salt16 | iv16 | AES-128-CBC 密文 | HMAC-SHA256
  3. sign_p256       ECDSA P-256 / SHA-256 设备签名（新版 ExchangeToken 必需）

不联网、不写盘、不打印任何密钥或 token。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any

# ── 桌面端 tc 加密常量（社区公开的客户端逆向结果，非密钥材料）────────────
_SALT_A = bytes([
    82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
    124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
    84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
    8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
])
_SALT_B = bytes([
    31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
    96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
    160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
    23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
])
_SALT_AES = bytes(a ^ b for a, b in zip(_SALT_A, _SALT_B))
_TC_HEADER = b"tc\x05\x10\x00\x00"

_STATE_MAGIC = b"TCC1"
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


class CryptoError(Exception):
    """解密 / 加密 / 签名失败。"""


# ══════════════════════ AES-128（内置最小实现）══════════════════════
def _gmul(a: int, b: int) -> int:
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return product


def _build_sbox() -> tuple[list[int], list[int]]:
    inverse = [0] * 256
    for i in range(1, 256):
        for j in range(1, 256):
            if _gmul(i, j) == 1:
                inverse[i] = j
                break
    sbox = []
    for i in range(256):
        x = inverse[i] if i else 0
        s = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sbox.append(s ^ 0x63)
    inv = [0] * 256
    for index, value in enumerate(sbox):
        inv[value] = index
    return sbox, inv


_SBOX, _INV_SBOX = _build_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise CryptoError("AES 密钥必须是 16 字节")
    words = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    return [[words[4 * r + c][k] for c in range(4) for k in range(4)] for r in range(11)]


def _add_key(state: list[int], round_key: list[int]) -> list[int]:
    return [a ^ b for a, b in zip(state, round_key)]


def _shift(state: list[int]) -> list[int]:
    idx = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
    return [state[i] for i in idx]


def _ishift(state: list[int]) -> list[int]:
    idx = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
    return [state[i] for i in idx]


def _mix(state: list[int]) -> list[int]:
    out = []
    for c in range(4):
        a = state[c * 4:c * 4 + 4]
        out += [
            _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3],
            a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3],
            a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3),
            _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2),
        ]
    return out


def _imix(state: list[int]) -> list[int]:
    out = []
    for c in range(4):
        a = state[c * 4:c * 4 + 4]
        out += [
            _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9),
            _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13),
            _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11),
            _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14),
        ]
    return out


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    """单块 ECB 加密（同时用于验证 FIPS-197 标准测试向量）。"""
    if len(block) != 16:
        raise CryptoError("AES 块必须是 16 字节")
    rk = _expand_key(key)
    state = _add_key(list(block), rk[0])
    for r in range(1, 10):
        state = _add_key(_mix(_shift([_SBOX[b] for b in state])), rk[r])
    state = _add_key(_shift([_SBOX[b] for b in state]), rk[10])
    return bytes(state)


def aes128_decrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise CryptoError("AES 块必须是 16 字节")
    rk = _expand_key(key)
    state = _add_key(list(block), rk[10])
    for r in range(9, 0, -1):
        state = _imix(_add_key(_ishift([_INV_SBOX[b] for b in state]), rk[r]))
    state = _add_key(_ishift([_INV_SBOX[b] for b in state]), rk[0])
    return bytes(state)


def _pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - len(data) % 16
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("空明文")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("PKCS7 填充不合法")
    return data[:-pad]


def aes128_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    rk = _expand_key(key)
    padded = _pkcs7_pad(plaintext)
    previous, out = list(iv), bytearray()
    for offset in range(0, len(padded), 16):
        block = list(padded[offset:offset + 16])
        state = _add_key([a ^ b for a, b in zip(block, previous)], rk[0])
        for r in range(1, 10):
            state = _add_key(_mix(_shift([_SBOX[b] for b in state])), rk[r])
        state = _add_key(_shift([_SBOX[b] for b in state]), rk[10])
        out += bytes(state)
        previous = state
    return bytes(out)


def aes128_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % 16:
        raise CryptoError("CBC 密文长度不合法")
    rk = _expand_key(key)
    previous, out = list(iv), bytearray()
    for offset in range(0, len(ciphertext), 16):
        block = list(ciphertext[offset:offset + 16])
        state = _add_key(block, rk[10])
        for r in range(9, 0, -1):
            state = _imix(_add_key(_ishift([_INV_SBOX[b] for b in state]), rk[r]))
        state = _add_key(_ishift([_INV_SBOX[b] for b in state]), rk[0])
        out += bytes(a ^ b for a, b in zip(state, previous))
        previous = block
    return bytes(out)


# ══════════════════════ 桌面端凭据 ══════════════════════
def norm_pem(value: str) -> str:
    """把粘贴时字面的 \\n 还原成真换行。"""
    v = (value or "").strip()
    if "\\n" in v and "\n" not in v:
        v = v.replace("\\n", "\n")
    return v


def tc_decrypt(value: Any) -> dict:
    """解密 storage.json 中 iCubeAuthInfo://* 的值，返回 dict。

    兼容明文 dict / 明文 JSON 字符串 / tc 加密串。
    密文结构：6B 头 + 32B enc_key + AES-128-CBC 密文，
    明文为 64B SHA512 校验 + JSON + PKCS7(或零) 填充。
    """
    if isinstance(value, dict):
        return value
    text = str(value or "").strip()
    if not text:
        raise CryptoError("空的凭据值")
    if text.startswith("{"):
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise CryptoError("明文凭据不是 JSON 对象")
        return parsed
    try:
        raw = base64.b64decode(text)
    except Exception as exc:
        raise CryptoError("凭据不是合法的 base64 / JSON") from exc
    if len(raw) < 38 or raw[:6] != _TC_HEADER:
        raise CryptoError("tc 头不匹配，凭据格式可能已变更")

    enc_key, ciphertext = raw[6:38], raw[38:]
    if len(ciphertext) % 16:
        raise CryptoError("密文长度不是 16 的倍数")
    h1 = hashlib.sha512(enc_key).digest()
    h2 = hashlib.sha512(h1 + _SALT_AES).digest()
    padded = aes128_cbc_decrypt(h2[:16], h2[16:32], ciphertext)
    try:
        plain = _pkcs7_unpad(padded)
    except ValueError:
        plain = padded.rstrip(b"\x00").rstrip()
    if len(plain) < 65:
        raise CryptoError("解密结果过短")
    stored_hash, body = plain[:64], plain[64:]
    if not hmac.compare_digest(hashlib.sha512(body).digest(), stored_hash):
        raise CryptoError("SHA512 校验失败，凭据可能已损坏")
    try:
        result = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise CryptoError("解密结果不是合法 JSON") from exc
    if not isinstance(result, dict):
        raise CryptoError("解密结果不是 JSON 对象")
    return result


# ══════════════════════ 云端状态加密 ══════════════════════
def _state_master(salt: bytes) -> tuple[bytes, bytes]:
    key = os.environ.get("STATE_KEY", "").strip()
    if not key:
        raise CryptoError("缺少 STATE_KEY（用于加密轮换后的 token 状态文件）")
    master = hashlib.sha256(key.encode("utf-8") + salt).digest()
    return master[:16], master[16:]


def encrypt_state(payload: dict) -> bytes:
    """加密成可安全提交进私有仓库的字节串（每次随机 salt / iv）。"""
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    salt, iv = os.urandom(16), os.urandom(16)
    enc_key, mac_key = _state_master(salt)
    ciphertext = aes128_cbc_encrypt(enc_key, iv, raw)
    head = _STATE_MAGIC + salt + iv
    mac = hmac.new(mac_key, head + ciphertext, hashlib.sha256).digest()
    return head + ciphertext + mac


def decrypt_state(blob: bytes) -> dict:
    if len(blob) < 4 + 16 + 16 + 16 + 32 or blob[:4] != _STATE_MAGIC:
        raise CryptoError("状态文件格式不对")
    salt, iv = blob[4:20], blob[20:36]
    ciphertext, mac = blob[36:-32], blob[-32:]
    enc_key, mac_key = _state_master(salt)
    expected = hmac.new(mac_key, blob[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise CryptoError("状态文件校验失败（STATE_KEY 变了或文件被改过）")
    try:
        plain = _pkcs7_unpad(aes128_cbc_decrypt(enc_key, iv, ciphertext))
        data = json.loads(plain.decode("utf-8"))
    except Exception as exc:
        raise CryptoError("状态文件解密失败") from exc
    if not isinstance(data, dict):
        raise CryptoError("状态文件内容不是对象")
    return data


# ══════════════════════ ECDSA P-256 设备签名 ══════════════════════
def _der_tlv(buf: bytes, i: int):
    tag, length = buf[i], buf[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, buf[i:i + length], i + length


def _pem_der(pem: str) -> bytes:
    body = "".join(line.strip() for line in pem.splitlines() if "---" not in line)
    return base64.b64decode(body)


def _private_scalar(pem: str) -> int:
    der = _pem_der(pem)
    try:  # PKCS#8
        _, body, _ = _der_tlv(der, 0)
        i = 0
        _, _, i = _der_tlv(body, i)
        _, _, i = _der_tlv(body, i)
        _, octets, _ = _der_tlv(body, i)
        _, inner, _ = _der_tlv(octets, 0)
        j = 0
        _, _, j = _der_tlv(inner, j)
        _, d, _ = _der_tlv(inner, j)
    except Exception:  # SEC1
        _, body, _ = _der_tlv(der, 0)
        i = 0
        _, _, i = _der_tlv(body, i)
        _, d, _ = _der_tlv(body, i)
    return int.from_bytes(d, "big")


def _public_point(pem: str) -> tuple[int, int]:
    """从 SPKI PEM 取出未压缩公钥点 (x, y)。"""
    der = _pem_der(pem)
    _, body, _ = _der_tlv(der, 0)
    i = 0
    _, _, i = _der_tlv(body, i)      # AlgorithmIdentifier
    _, bits, _ = _der_tlv(body, i)   # BIT STRING
    point = bits[1:]                 # 丢掉 unused-bits 字节
    if len(point) != 65 or point[0] != 0x04:
        raise CryptoError("公钥不是未压缩 P-256 点")
    return (int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:65], "big"))


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    return x3, (lam * (x1 - x3) - y1) % _P256_P


def _ec_mul(k: int, point):
    result = None
    while k:
        if k & 1:
            result = _ec_add(result, point)
        point = _ec_add(point, point)
        k >>= 1
    return result


def _enc_int(value: int) -> bytes:
    b = value.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def _der_ints(sig: bytes) -> tuple[int, int]:
    if not sig or sig[0] != 0x30:
        raise CryptoError("非 DER 签名")
    i = 2
    if sig[1] & 0x80:
        i = 2 + (sig[1] & 0x7F)
    out = []
    for _ in range(2):
        if i >= len(sig) or sig[i] != 0x02:
            raise CryptoError("DER 签名字段异常")
        length = sig[i + 1]
        out.append(int.from_bytes(sig[i + 2:i + 2 + length], "big"))
        i += 2 + length
    return out[0], out[1]


def sign_p256(private_pem: str, data: bytes) -> str:
    """ECDSA P-256 / SHA-256 签名，返回 base64(DER)，并做低 s 归一化。"""
    try:
        d = _private_scalar(norm_pem(private_pem))
    except Exception as exc:
        raise CryptoError("设备私钥不是合法 PEM") from exc
    z = int.from_bytes(hashlib.sha256(data).digest(), "big")
    while True:
        k = int.from_bytes(os.urandom(32), "big") % (_P256_N - 1) + 1
        x1, _ = _ec_mul(k, (_P256_GX, _P256_GY))
        r = x1 % _P256_N
        if r == 0:
            continue
        s = (pow(k, -1, _P256_N) * (z + r * d)) % _P256_N
        if s == 0:
            continue
        if s > _P256_N // 2:
            s = _P256_N - s
        body = _enc_int(r) + _enc_int(s)
        return base64.b64encode(b"\x30" + bytes([len(body)]) + body).decode("ascii")


def verify_p256(public_pem: str, data: bytes, signature: bytes) -> bool:
    """验签（离线自测用）。"""
    try:
        r, s = _der_ints(signature)
        q = _public_point(norm_pem(public_pem))
        z = int.from_bytes(hashlib.sha256(data).digest(), "big")
        w = pow(s, -1, _P256_N)
        point = _ec_add(_ec_mul(z * w % _P256_N, (_P256_GX, _P256_GY)),
                        _ec_mul(r * w % _P256_N, q))
        return point is not None and point[0] % _P256_N == r
    except Exception:
        return False
