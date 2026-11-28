#!/usr/bin/env node
/**
 * 一键把本机 Trae 登录态推到 GitHub Secret。
 *
 * 背景：Trae 的 refreshToken 是轮换制，本机客户端一刷新，云端持有的旧值就作废
 * （表现是 code=1001「unable to authenticate」）。所以云端不能长期吃静态 Secret，
 * 需要用本脚本按需（或定时）把最新登录态推上去，并带上 rev 让云端知道「这是人工更新的」。
 *
 * 用法（在仓库根目录）：
 *   set GITHUB_TOKEN=github_pat_xxx
 *   node tools/push_secret.js --secret TRAE_ACCOUNTS_2
 *
 * 依赖：node 18+、npm i libsodium-wrappers（在本目录执行）、python（导出登录态）
 * 不会把 token 写到任何文件，也不会打印明文。
 */
'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const nodeCrypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_REPO = 'powerwowowowo/Trae-Cloud-Checkin';

function fail(msg) {
  console.error('[x] ' + msg);
  process.exit(1);
}

function argOf(name, fallback) {
  const i = process.argv.indexOf('--' + name);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const repo = argOf('repo', process.env.TRAE_REPO || DEFAULT_REPO);
const secretName = argOf('secret', 'TRAE_ACCOUNTS_2');
const token = process.env.GITHUB_TOKEN || process.env.GH_PAT || '';
const python = argOf('python', process.env.PYTHON || 'python');
if (!token) fail('缺少 GITHUB_TOKEN（写 Secret 需要 repo 的 secrets:write 权限）');

function request(method, url, body, extraHeaders) {
  const headers = Object.assign(
    {
      'User-Agent': 'trae-checkin-push',
      Accept: 'application/vnd.github+json',
      Authorization: 'Bearer ' + token,
    },
    extraHeaders || {}
  );
  if (body) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(body);
  }
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method, headers }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(30000, () => req.destroy(new Error('timeout')));
    if (body) req.write(body);
    req.end();
  });
}

function resolveSecret(account) {
  if (secretName !== 'auto') return secretName;
  const mapPath = path.join(
    process.env.USERPROFILE || os.homedir(),
    '.workbuddy',
    'trae-checkin',
    'map.json'
  );
  let map = {};
  try {
    map = JSON.parse(fs.readFileSync(mapPath, 'utf8'));
  } catch (e) {
    /* 没有映射表就退回默认槽位 */
  }
  const tail = String(account.userId || '').slice(-4);
  return map[tail] || 'TRAE_ACCOUNTS_2';
}

function localStatePath() {
  const base = process.env.LOCALAPPDATA || path.join(os.homedir(), '.cache');
  return path.join(base, 'TraeCheckin', 'last.json');
}

function readState() {
  try {
    return JSON.parse(fs.readFileSync(localStatePath(), 'utf8')) || {};
  } catch (e) {
    return {};
  }
}

function writeState(state) {
  const p = localStatePath();
  try {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(state, null, 2));
  } catch (e) {
    /* 记录失败只影响去重，不影响推送 */
  }
}

function exportCredentials() {
  let out;
  try {
    out = execFileSync(python, [path.join(ROOT, 'tools', 'export_credentials.py')], {
      cwd: ROOT,
      encoding: 'utf8',
      maxBuffer: 8 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch (e) {
    fail('导出登录态失败（本机 Trae 客户端是否登录过？）：' + (e.message || e));
  }
  const start = out.indexOf('{');
  const end = out.lastIndexOf('}');
  if (start < 0 || end < start) fail('导出结果里没有 JSON');
  let obj;
  try {
    obj = JSON.parse(out.slice(start, end + 1));
  } catch (e) {
    fail('导出结果不是合法 JSON：' + e.message);
  }
  if (Array.isArray(obj)) {
    if (obj.length !== 1) fail('本机导出到 ' + obj.length + ' 个账号，请手动拆分到不同 Secret');
    obj = obj[0];
  }
  return obj;
}

(async () => {
  const sodium = require('libsodium-wrappers');
  await sodium.ready;

  const account = exportCredentials();
  const target = resolveSecret(account);
  const force = process.argv.includes('--force');
  const key = String(account.userId || '') + '|' + target;
  const tag = nodeCrypto
    .createHash('sha256')
    .update(String(account.accessToken || '') + '|' + String(account.refreshToken || ''))
    .digest('hex')
    .slice(0, 16);
  const localState = readState();
  if (!force && localState[key] && localState[key].tag === tag) {
    console.log('[=] 本机登录态没变，跳过推送（云端继续用自己的轮换结果更安全）');
    return;
  }

  account.rev = 'r' + Date.now();
  const value = JSON.stringify(account);

  const pkRes = await request(
    'GET',
    'https://api.github.com/repos/' + repo + '/actions/secrets/public-key'
  );
  if (pkRes.status !== 200) fail('取公钥失败 HTTP ' + pkRes.status + ' ' + pkRes.body.slice(0, 120));
  const pk = JSON.parse(pkRes.body);

  const sealed = sodium.crypto_box_seal(
    sodium.from_string(value),
    new Uint8Array(Buffer.from(pk.key, 'base64'))
  );
  const putBody = JSON.stringify({
    encrypted_value: Buffer.from(sealed).toString('base64'),
    key_id: pk.key_id,
  });
  const putRes = await request(
    'PUT',
    'https://api.github.com/repos/' + repo + '/actions/secrets/' + encodeURIComponent(target),
    putBody
  );
  if (putRes.status !== 201 && putRes.status !== 204) {
    fail('写 Secret 失败 HTTP ' + putRes.status + ' ' + putRes.body.slice(0, 120));
  }
  localState[key] = { tag: tag, rev: account.rev, pushedAt: new Date().toISOString() };
  writeState(localState);
  console.log(
    '[+] 已更新 ' + repo + ' 的 ' + target +
      '：账号尾号 ' + String(account.userId || '').slice(-4) +
      '，rev=' + account.rev
  );
})().catch((e) => fail(e && e.stack ? e.stack : String(e)));
