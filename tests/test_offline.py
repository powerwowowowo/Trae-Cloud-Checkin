#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线单元测试：不联网、不需要真实账号，覆盖解密 / 加密 / 签名 / 请求头 / 签到分支。"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
import urllib.error
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import checkin  # noqa: E402
from lib import crypto, state, trae_api  # noqa: E402


def _der(tag: int, content: bytes) -> bytes:
    """构造测试用 DER TLV（长度均小于 128 字节）。"""
    return bytes([tag, len(content)]) + content


def _pem(label: str, der: bytes) -> str:
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[i:i + 64] for i in range(0, len(encoded), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)


def make_p256_pem(scalar: int) -> tuple[str, str]:
    """纯标准库造一对 SEC1 私钥 / SPKI 公钥 PEM，用于验签自测。"""
    x, y = crypto._ec_mul(scalar, (crypto._P256_GX, crypto._P256_GY))
    point = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    curve_oid = bytes.fromhex("06082A8648CE3D030107")
    ec_oid = bytes.fromhex("06072A8648CE3D0201")
    spki = _der(0x30, _der(0x30, ec_oid + curve_oid) + _der(0x03, b"\x00" + point))
    sec1 = _der(0x30, _der(0x02, b"\x01")
                + _der(0x04, scalar.to_bytes(32, "big"))
                + _der(0xA0, curve_oid)
                + _der(0xA1, _der(0x03, b"\x00" + point)))
    return _pem("EC PRIVATE KEY", sec1), _pem("PUBLIC KEY", spki)


def make_tc_cipher(obj: dict) -> str:
    """按桌面端格式造一段 tc 密文，用于验证解密实现。"""
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    plain = hashlib.sha512(body).digest() + body
    enc_key = os.urandom(32)
    h = hashlib.sha512(hashlib.sha512(enc_key).digest() + crypto._SALT_AES).digest()
    ciphertext = crypto.aes128_cbc_encrypt(h[:16], h[16:32], plain)
    return base64.b64encode(crypto._TC_HEADER + enc_key + ciphertext).decode("ascii")


class TestAes(unittest.TestCase):
    def test_fips197_known_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(crypto.aes128_encrypt_block(key, plain), cipher)
        self.assertEqual(crypto.aes128_decrypt_block(key, cipher), plain)

    def test_cbc_roundtrip(self):
        key, iv = os.urandom(16), os.urandom(16)
        data = os.urandom(257)
        padded = crypto.aes128_cbc_decrypt(key, iv,
                                           crypto.aes128_cbc_encrypt(key, iv, data))
        # unpad 由调用方负责（tc 老版本可能用零填充，需要 fallback）
        self.assertEqual(crypto._pkcs7_unpad(padded), data)


class TestTcDecrypt(unittest.TestCase):
    def test_roundtrip(self):
        value = make_tc_cipher({"token": "AT-123", "refreshToken": "RT-456", "userId": "42"})
        self.assertEqual(crypto.tc_decrypt(value)["refreshToken"], "RT-456")

    def test_plain_json_and_dict(self):
        self.assertEqual(crypto.tc_decrypt('{"token":"a"}')["token"], "a")
        self.assertEqual(crypto.tc_decrypt({"token": "a"})["token"], "a")

    def test_bad_header_rejected(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.tc_decrypt(base64.b64encode(b"xxxxxx" + b"\x00" * 40).decode())

    def test_hash_mismatch_rejected(self):
        value = make_tc_cipher({"token": "a"})
        raw = bytearray(base64.b64decode(value))
        raw[-1] ^= 0x01  # 破坏最后一个密文块
        with self.assertRaises(crypto.CryptoError):
            crypto.tc_decrypt(base64.b64encode(bytes(raw)).decode())


class TestStateEncryption(unittest.TestCase):
    def test_encrypt_decrypt_no_plaintext(self):
        with patch.dict(os.environ, {"STATE_KEY": "unit-test-key"}):
            blob = crypto.encrypt_state({"accounts": [{"accessToken": "TOPSECRET-TOKEN"}]})
            self.assertNotIn(b"TOPSECRET-TOKEN", blob)
            self.assertEqual(crypto.decrypt_state(blob)["accounts"][0]["accessToken"],
                             "TOPSECRET-TOKEN")

    def test_wrong_key_fails(self):
        with patch.dict(os.environ, {"STATE_KEY": "key-a"}):
            blob = crypto.encrypt_state({"a": 1})
        with patch.dict(os.environ, {"STATE_KEY": "key-b"}):
            with self.assertRaises(crypto.CryptoError):
                crypto.decrypt_state(blob)

    def test_missing_key_fails(self):
        env = os.environ.copy()
        env.pop("STATE_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(crypto.CryptoError):
                crypto.encrypt_state({"a": 1})

    def test_tamper_detected(self):
        with patch.dict(os.environ, {"STATE_KEY": "unit-test-key"}):
            blob = bytearray(crypto.encrypt_state({"a": 1}))
            blob[-1] ^= 0x01
            with self.assertRaises(crypto.CryptoError):
                crypto.decrypt_state(bytes(blob))


class TestDeviceSignature(unittest.TestCase):
    def test_signature_verifies_and_low_s(self):
        private_pem, public_pem = make_p256_pem(0x123456789ABCDEF)
        data = b"POST\n/trae/api/v3/oauth/ExchangeToken"
        signature = base64.b64decode(crypto.sign_p256(private_pem, data))
        self.assertTrue(crypto.verify_p256(public_pem, data, signature))
        _r, s = crypto._der_ints(signature)
        self.assertLessEqual(s, crypto._P256_N // 2)

    def test_wrong_message_fails(self):
        private_pem, public_pem = make_p256_pem(0x987654321)
        signature = base64.b64decode(crypto.sign_p256(private_pem, b"a"))
        self.assertFalse(crypto.verify_p256(public_pem, b"b", signature))

    def test_literal_newline_pem(self):
        private_pem, _ = make_p256_pem(0x2468ACE)
        one_line = private_pem.replace("\n", "\\n").strip()
        self.assertIsInstance(crypto.sign_p256(one_line, b"data"), str)


class TestApiContract(unittest.TestCase):
    def test_headers(self):
        headers = trae_api.ug_headers({
            "accessToken": "AT", "deviceId": "1234567890123",
            "fingerprint": {"brand": "PC", "type": "Windows", "os": "10.0.19045"},
        })
        self.assertEqual(headers["Authorization"], "Cloud-IDE-JWT AT")
        self.assertEqual(headers["x-device-id"], "1234567890123")
        self.assertNotIn("X-Device-Id", headers)  # 双头会被风控判异常
        self.assertEqual(headers["X-User-Region"], "CN")
        self.assertEqual(headers["x-app-version"], trae_api.IDE_VERSION)

    def test_request_body(self):
        self.assertEqual(json.loads(trae_api.REQ_BODY), {"req_source": 1})

    def test_endpoints(self):
        self.assertTrue(trae_api.EP_STATUS.endswith("/checkin_credits/status"))
        self.assertTrue(trae_api.EP_CLAIM.endswith("/checkin_credits/claim"))
        self.assertIn("api.trae.cn", trae_api.EP_EXCHANGE_PROOF)

    def test_decode_uid(self):
        payload = base64.urlsafe_b64encode(json.dumps({"data": {"id": "9988"}}).encode()).decode().rstrip("=")
        self.assertEqual(trae_api.decode_uid("x." + payload + ".y"), "9988")
        self.assertEqual(trae_api.decode_uid("garbage"), "")

    def test_needs_refresh(self):
        self.assertTrue(trae_api.needs_refresh({}))
        self.assertFalse(trae_api.needs_refresh({"expiresAt": 9999999999}))
        self.assertTrue(trae_api.needs_refresh({"expiresAt": 1}))


class TestHttpRetry(unittest.TestCase):
    """一天只跑一轮定时，容错靠 post() 内部的有限退避重试。"""

    class _Resp:
        def __init__(self, status, body):
            self.status = status
            self.body = body.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return self.body

    @staticmethod
    def _http_error(code):
        return urllib.error.HTTPError("https://example.invalid", code, "err", {},
                                      io.BytesIO(b'{"code":0}'))

    def _post(self, effects, retries=2):
        calls = []

        def fake(req, timeout=None):
            calls.append(req)
            item = effects[len(calls) - 1]
            if isinstance(item, BaseException):
                raise item
            return item

        with patch("urllib.request.urlopen", side_effect=fake), patch("time.sleep"):
            result = trae_api.post("https://example.invalid/p", {}, "{}", retries=retries)
        return result, len(calls)

    def test_5xx_retried_then_success(self):
        effects = [self._http_error(503), self._http_error(502), self._Resp(200, '{"code":0}')]
        (status, text), calls = self._post(effects)
        self.assertEqual((status, json.loads(text)["code"]), (200, 0))
        self.assertEqual(calls, 3)

    def test_429_retried(self):
        (status, _), calls = self._post([self._http_error(429), self._Resp(200, '{"code":0}')])
        self.assertEqual((status, calls), (200, 2))

    def test_network_error_retried(self):
        effects = [OSError("timeout"), OSError("timeout"), self._Resp(200, "{}")]
        (status, _), calls = self._post(effects)
        self.assertEqual((status, calls), (200, 3))

    def test_business_200_never_retried(self):
        effects = [self._Resp(200, '{"code":9074,"message":"限流"}')]
        (status, text), calls = self._post(effects)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(text)["code"], 9074)
        self.assertEqual(calls, 1)  # 业务限流码不能触发 HTTP 层重试

    def test_4xx_not_retried(self):
        (status, _), calls = self._post([self._http_error(401)])
        self.assertEqual((status, calls), (401, 1))

    def test_retries_exhausted_returns_last_code(self):
        effects = [self._http_error(503) for _ in range(3)]
        (status, _), calls = self._post(effects)
        self.assertEqual((status, calls), (503, 3))


class TestStateMerge(unittest.TestCase):
    def test_rotation_is_merged_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = state.STATE_FILE
            state.STATE_FILE = Path(tmp) / "credentials.enc"
            try:
                with patch.dict(os.environ, {"STATE_KEY": "unit-test-key"}):
                    state.save_accounts([{
                        "name": "a", "userId": "1", "deviceId": "1234567890123",
                        "accessToken": "NEW-AT", "refreshToken": "NEW-RT", "expiresAt": 9999999999,
                    }])
                    secret = json.dumps([{
                        "name": "a", "userId": "1", "deviceId": "1234567890123",
                        "accessToken": "OLD-AT", "refreshToken": "OLD-RT",
                    }])
                    accounts, note = state.load_accounts(secret)
                    self.assertEqual(accounts[0]["refreshToken"], "NEW-RT")
                    self.assertIn("状态文件", note)
            finally:
                state.STATE_FILE = original

    def test_missing_secret(self):
        with self.assertRaises(state.ConfigError):
            state.load_accounts("")

    def test_alias_normalization(self):
        acc = state.normalize({"nickname": "n", "token": "AT", "deviceKeyPem": "PEM",
                               "claimDeviceId": "1234567890123", "uid": "7"})
        self.assertEqual(acc["accessToken"], "AT")
        self.assertEqual(acc["deviceId"], "1234567890123")
        self.assertEqual(acc["devicePrivateKeyPem"], "PEM")

    def test_device_id_required(self):
        with self.assertRaisesRegex(state.ConfigError, "deviceId"):
            state.load_accounts(json.dumps([{"accessToken": "AT", "refreshToken": "RT"}]))


class TestCheckinBranches(unittest.TestCase):
    def setUp(self):
        self.acc = {
            "name": "a", "userId": "1", "accessToken": "AT", "refreshToken": "RT",
            "deviceId": "1234567890123", "expiresAt": 9999999999,
            "fingerprint": {"type": "Windows", "os": "10.0.19045"},
        }

    def _run(self, statuses, claimed, verify=True):
        with patch.object(trae_api, "needs_refresh", return_value=False), \
             patch.object(trae_api, "status_of", side_effect=statuses), \
             patch.object(trae_api, "claim", return_value=claimed) as claim_mock:
            result = checkin.run_account(dict(self.acc), verify=verify)
            return result, claim_mock

    def test_already_checked_in_skips_claim(self):
        result, claim_mock = self._run(
            [{"code": 0, "checked_in": True, "credits": 600, "_http": 200}], {})
        self.assertEqual(result["state"], "ALREADY")
        self.assertEqual(result["credits"], 600)
        claim_mock.assert_not_called()

    def test_claim_confirmed(self):
        result, _ = self._run(
            [{"code": 0, "checked_in": False, "credits": 0, "_http": 200},
             {"code": 0, "checked_in": True, "credits": 100, "_http": 200}],
            {"code": 0, "data": {"points": 100}, "_http": 200})
        self.assertEqual(result["state"], "OK")
        self.assertEqual(result["points"], 100)

    def test_unconfirmed_reported(self):
        result, _ = self._run(
            [{"code": 0, "checked_in": False, "_http": 200},
             {"code": 0, "checked_in": False, "_http": 200}],
            {"code": 0, "data": {"points": 100}, "_http": 200})
        self.assertEqual(result["state"], "UNCONFIRMED")

    def test_9074_no_retry(self):
        result, claim_mock = self._run(
            [{"code": 0, "checked_in": False, "_http": 200}],
            {"code": 9074, "message": "当前参与用户太多", "_http": 200})
        self.assertEqual(result["state"], "RATE_LIMITED")
        self.assertEqual(claim_mock.call_count, 1)  # 当场连发会延长惩罚窗口

    def test_already_codes(self):
        for code in trae_api.ALREADY_CODES:
            result, _ = self._run(
                [{"code": 0, "checked_in": False, "_http": 200}],
                {"code": code, "message": "已签", "_http": 200})
            self.assertEqual(result["state"], "ALREADY")

    def test_dry_run_never_claims(self):
        with patch.object(trae_api, "needs_refresh", return_value=False), \
             patch.object(trae_api, "status_of",
                          return_value={"code": 0, "checked_in": False, "_http": 200}), \
             patch.object(trae_api, "claim") as claim_mock:
            result = checkin.run_account(dict(self.acc), dry_run=True)
            self.assertEqual(result["state"], "DRY_RUN")
            claim_mock.assert_not_called()


class TestEndToEnd(unittest.TestCase):
    """mock 掉网络，跑完整 main()：结果汇总 + 状态写回 + 不泄漏 token。"""

    ACCOUNT = {
        "name": "e2e", "userId": "7788", "deviceId": "1234567890123",
        "accessToken": "SUPER-SECRET-AT", "refreshToken": "SUPER-SECRET-RT",
        "expiresAt": 9999999999,
        "fingerprint": {"type": "Windows", "os": "10.0.19045"},
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.orig_result, self.orig_state = checkin.RESULT_FILE, state.STATE_FILE
        checkin.RESULT_FILE = self.tmp_path / "result.json"
        state.STATE_FILE = self.tmp_path / "credentials.enc"
        self.env = {
            "TRAE_ACCOUNTS": json.dumps([self.ACCOUNT]),
            "STATE_KEY": "e2e-key",
        }

    def tearDown(self):
        checkin.RESULT_FILE, state.STATE_FILE = self.orig_result, self.orig_state
        self.tmp.cleanup()

    def test_full_run_writes_summary_and_encrypted_state(self):
        statuses = [
            {"code": 0, "checked_in": False, "credits": 0, "_http": 200},
            {"code": 0, "checked_in": True, "credits": 100, "_http": 200},
        ]
        with patch.dict(os.environ, self.env, clear=True), \
             patch.object(sys, "argv", ["checkin.py"]), \
             patch.object(trae_api, "needs_refresh", return_value=False), \
             patch.object(trae_api, "status_of", side_effect=statuses), \
             patch.object(trae_api, "claim", return_value={"code": 0, "data": {"points": 100}, "_http": 200}), \
             patch.object(checkin, "notify"):
            code = checkin.main()
        self.assertEqual(code, 0)
        text = checkin.RESULT_FILE.read_text(encoding="utf-8")
        self.assertNotIn("SUPER-SECRET-AT", text)
        summary = json.loads(text)
        self.assertTrue(summary["success"])
        self.assertEqual(summary["results"][0]["state"], "OK")
        self.assertEqual(summary["counts"]["OK"], 1)
        blob = state.STATE_FILE.read_bytes()
        self.assertNotIn(b"SUPER-SECRET-RT", blob)
        with patch.dict(os.environ, {"STATE_KEY": "e2e-key"}):
            saved = crypto.decrypt_state(blob)
        self.assertEqual(saved["accounts"][0]["refreshToken"], "SUPER-SECRET-RT")

    def test_dry_run_does_not_claim_or_write_state(self):
        with patch.dict(os.environ, self.env, clear=True), \
             patch.object(sys, "argv", ["checkin.py", "--dry-run", "--no-save"]), \
             patch.object(trae_api, "needs_refresh", return_value=False), \
             patch.object(trae_api, "status_of",
                          return_value={"code": 0, "checked_in": False, "_http": 200}), \
             patch.object(trae_api, "claim") as claim_mock, \
             patch.object(checkin, "notify"):
            code = checkin.main()
        self.assertEqual(code, 0)
        claim_mock.assert_not_called()
        self.assertFalse(state.STATE_FILE.exists())
        self.assertEqual(json.loads(checkin.RESULT_FILE.read_text(encoding="utf-8"))
                         ["results"][0]["state"], "DRY_RUN")


class TestMultiAccountSecrets(unittest.TestCase):
    """加号用编号 Secret，不需要读取 / 覆盖已有的 TRAE_ACCOUNTS。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original = state.STATE_FILE
        state.STATE_FILE = Path(self.tmp.name) / "credentials.enc"
        self.base = {"accessToken": "AT", "refreshToken": "RT", "deviceId": "1234567890123"}

    def tearDown(self):
        state.STATE_FILE = self.original
        self.tmp.cleanup()

    def _acc(self, uid):
        return dict(self.base, userId=uid, name="u" + uid)

    def test_merge_numbered_secrets_in_order(self):
        env = {
            "TRAE_ACCOUNTS": json.dumps([self._acc("1")]),
            "TRAE_ACCOUNTS_2": json.dumps([self._acc("2")]),
            "TRAE_ACCOUNTS_9": json.dumps([self._acc("9")]),
        }
        with patch.dict(os.environ, env, clear=True):
            accounts, note = state.load_accounts()
        self.assertEqual([a["userId"] for a in accounts], ["1", "2", "9"])
        for name in env:
            self.assertIn(name, note)

    def test_same_secret_can_hold_multiple_accounts(self):
        env = {
            "TRAE_ACCOUNTS": json.dumps([self._acc("1"), self._acc("2")]),
            "TRAE_ACCOUNTS_2": json.dumps([self._acc("3")]),
        }
        with patch.dict(os.environ, env, clear=True):
            accounts, _ = state.load_accounts()
        self.assertEqual([a["userId"] for a in accounts], ["1", "2", "3"])

    def test_duplicate_identity_is_deduplicated(self):
        env = {
            "TRAE_ACCOUNTS": json.dumps([self._acc("1")]),
            "TRAE_ACCOUNTS_2": json.dumps([self._acc("1"), self._acc("2")]),
        }
        with patch.dict(os.environ, env, clear=True):
            accounts, _ = state.load_accounts()
        self.assertEqual([a["userId"] for a in accounts], ["1", "2"])

    def test_only_numbered_secret_is_enough(self):
        with patch.dict(os.environ, {"TRAE_ACCOUNTS_2": json.dumps([self._acc("2")])}, clear=True):
            accounts, note = state.load_accounts()
        self.assertEqual(len(accounts), 1)
        self.assertIn("TRAE_ACCOUNTS_2", note)

    def test_bad_numbered_secret_reports_its_name(self):
        env = {"TRAE_ACCOUNTS": json.dumps([self._acc("1")]), "TRAE_ACCOUNTS_3": "{oops"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(state.ConfigError, "TRAE_ACCOUNTS_3"):
                state.load_accounts()

    def test_all_empty_fails(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(state.ConfigError):
                state.load_accounts()

    def test_explicit_value_ignores_environment(self):
        env = {"TRAE_ACCOUNTS_2": json.dumps([self._acc("2")])}
        with patch.dict(os.environ, env, clear=True):
            accounts, _ = state.load_accounts(json.dumps([self._acc("1")]))
        self.assertEqual([a["userId"] for a in accounts], ["1"])


class TestDeviceDerivation(unittest.TestCase):
    """同一客户端切号导出的多账号共用 deviceId，会自动派生避免 9095。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original = state.STATE_FILE
        state.STATE_FILE = Path(self.tmp.name) / "credentials.enc"

    def tearDown(self):
        state.STATE_FILE = self.original
        self.tmp.cleanup()

    def _acc(self, uid, did="1234567890123456"):
        return {"name": "u" + uid, "userId": uid, "deviceId": did,
                "accessToken": "AT", "refreshToken": "RT"}

    def _load(self, accounts):
        with patch.dict(os.environ, {"TRAE_ACCOUNTS": json.dumps(accounts)}, clear=True):
            return state.load_accounts()

    def test_single_account_unchanged(self):
        accounts, note = self._load([self._acc("1")])
        self.assertEqual(accounts[0]["deviceId"], "1234567890123456")
        self.assertNotIn("派生", note)

    def test_duplicate_device_ids_are_separated(self):
        accounts, note = self._load([self._acc("1"), self._acc("2")])
        first, second = accounts[0]["deviceId"], accounts[1]["deviceId"]
        self.assertNotEqual(first, second)
        self.assertTrue(second.isdigit() and len(second) == len(first))
        self.assertIn("派生", note)

    def test_three_accounts_all_distinct_and_stable(self):
        env = {"TRAE_ACCOUNTS": json.dumps([self._acc(str(i)) for i in range(3)])}
        with patch.dict(os.environ, env, clear=True):
            first, _ = state.load_accounts()
            second, _ = state.load_accounts()
        ids = [a["deviceId"] for a in first]
        self.assertEqual(len(set(ids)), 3)
        self.assertEqual(ids, [a["deviceId"] for a in second])

    def test_non_numeric_device_id_is_left_alone(self):
        accounts, _ = self._load([self._acc("1", "abc123"), self._acc("2", "abc123")])
        self.assertEqual([a["deviceId"] for a in accounts], ["abc123", "abc123"])

    def test_derivation_helper_never_reuses(self):
        used = {"1234567890123456", "1234567890123457"}
        new = state._derive_device_id("1234567890123456", used)
        self.assertNotIn(new, used)
        self.assertTrue(new.isdigit())


class TestTokenExpiry(unittest.TestCase):
    """storage.json 不带 expiresAt，必须从 JWT 推导，否则每轮都无谓续期。"""

    @staticmethod
    def _token(exp):
        payload = json.dumps({"data": {"id": "1"}, "exp": exp, "iat": int(time.time())}).encode()
        body = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        return "hdr." + body + ".sig"

    def test_exp_is_taken_from_jwt_and_no_needless_refresh(self):
        exp = int(time.time()) + 14 * 86400
        acc = state.normalize({"userId": "1", "deviceId": "1234567890123",
                               "accessToken": self._token(exp), "refreshToken": "RT"})
        self.assertIsNotNone(acc["expiresAt"])
        self.assertAlmostEqual(acc["expiresAt"], exp, delta=1)
        self.assertFalse(trae_api.needs_refresh(acc))

    def test_expired_token_still_needs_refresh(self):
        acc = state.normalize({"userId": "1", "deviceId": "1234567890123",
                               "accessToken": self._token(int(time.time()) - 60),
                               "refreshToken": "RT"})
        self.assertTrue(trae_api.needs_refresh(acc))

    def test_millisecond_exp_is_normalized(self):
        exp = int(time.time() * 1000) + 86400_000
        acc = state.normalize({"userId": "1", "deviceId": "1234567890123",
                               "accessToken": self._token(exp), "refreshToken": "RT"})
        self.assertLess(acc["expiresAt"], 1e12)

    def test_bad_token_keeps_exp_none(self):
        acc = state.normalize({"userId": "1", "deviceId": "1234567890123",
                               "accessToken": "not-a-jwt", "refreshToken": "RT"})
        self.assertIsNone(acc["expiresAt"])
        self.assertTrue(trae_api.needs_refresh(acc))


class TestPublicOutputMasking(unittest.TestCase):
    """公开仓库的日志与 result.json artifact 任何人可见，账号 ID 必须脱敏。"""

    def test_mask_uid(self):
        self.assertEqual(checkin._mask_uid("9000000000004346"), "***4346")
        self.assertEqual(checkin._mask_uid("123"), "***")
        self.assertEqual(checkin._mask_uid(""), "")

    def test_result_never_contains_full_uid(self):
        account = {"name": "a", "userId": "9000000000004346",
                   "deviceId": "1234567890123456",
                   "accessToken": "AT", "refreshToken": "RT"}
        with patch.object(trae_api, "needs_refresh", return_value=False), \
             patch.object(trae_api, "status_of",
                          return_value={"code": 0, "checked_in": True, "_http": 200}):
            result = checkin.run_account(account, dry_run=True)
        self.assertEqual(result["userId"], "***4346")
        self.assertNotIn("9000000000004346", json.dumps(result, ensure_ascii=False))
        self.assertEqual(result["deviceIdTail"], "3456")  # 只留尾号

    def test_internal_account_keeps_full_uid(self):
        """脱敏只作用于输出层，状态匹配仍需要完整 userId。"""
        raw = [{"name": "a", "userId": "9000000000004346",
                "deviceId": "1234567890123456", "accessToken": "AT", "refreshToken": "RT"}]
        with patch.dict(os.environ, {"TRAE_ACCOUNTS": json.dumps(raw)}, clear=True):
            accounts, _ = state.load_accounts()
        self.assertEqual(accounts[0]["userId"], "9000000000004346")


if __name__ == "__main__":
    unittest.main(verbosity=2)
