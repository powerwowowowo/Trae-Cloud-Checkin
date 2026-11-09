# Trae-Cloud-Checkin

Trae CN 每日积分云端自动签到。GitHub Actions 定时执行，不用开电脑、不用挂着客户端、不用装青龙面板。

仓库设为 **公开**：公开仓库的 GitHub Actions 标准 runner 不限分钟数，私有仓库只有 2000 分钟/月。
登录态以密文形式回写到仓库，密钥只存在 Actions Secrets 里；公开可见的日志与运行报告已做账号脱敏。
（想改回私有也行，功能不受影响，只是会重新计入分钟数额度。）

## 它跟本地方案的区别

| | 本地脚本 / 青龙面板 | 本仓库 |
| --- | --- | --- |
| 要不要开机 | 要 | 不要 |
| 登录态从哪来 | 实时读本机 `storage.json` | 一次性导出，放进 Secrets |
| token 过期 | 客户端自己续 | 云端用 refreshToken 续期并轮换 |
| 轮换后的 refreshToken | 写本地文件 | AES-128-CBC + HMAC-SHA256 加密后提交回仓库（密钥只在 Secrets） |
| 失败可见性 | 本地日志 | Actions 汇总 + 可选推送 |

## 三步跑起来

### 1. 本机导出凭证

在**装了 Trae CN / TRAE SOLO CN 并登录过**的那台机器上执行（Python 3.10+，纯标准库，无需安装任何依赖）：

```bash
git clone https://github.com/powerwowowowo/Trae-Cloud-Checkin.git
cd Trae-Cloud-Checkin
python tools/export_credentials.py
```

脚本只读 `storage.json`，输出一行 JSON（含 accessToken、refreshToken、真实设备号、设备私钥）。
**这行内容等同于账号密码，只往 GitHub Secrets 里放，别贴进任何文件、聊天或公开仓库。**

如果本机没装客户端，也可以用网页登录（手机号 / 验证码）：

```bash
python tools/login.py --device-id 1234567890123
```

但网页登录拿不到设备私钥，新版续期可能失败，长期无人值守优先用导出脚本。

### 2. 配置 Secrets

仓库 → Settings → Secrets and variables → Actions → New repository secret。

| Secret | 必填 | 说明 |
| --- | --- | --- |
| `TRAE_ACCOUNTS` | 至少一个 | 第一个账号，内容为上一步导出的整行 JSON 数组 |
| `TRAE_ACCOUNTS_2` … `_9` | 否 | 每多一个账号就新建一个编号 Secret，内容同样是导出的整行 JSON |
| `STATE_KEY` | 是 | 任意随机长字符串，用于加密轮换状态；生成后**不要再改** |
| `NOTIFY_WEBHOOK` | 否 | 企业微信机器人 webhook 完整地址 |
| `BARK_URL` | 否 | Bark 推送地址，例如 `https://api.day.app/你的Key` |
| `PUSHPLUS_TOKEN` | 否 | PushPlus token |

**多账号用编号 Secret，别往一个数组里塞。** GitHub Secret 只能写不能读，事后没法把新账号「追加」进已有的数组。
程序按 `TRAE_ACCOUNTS` → `_2` → … → `_9` 顺序合并，按 userId + deviceId 去重，已有 Secret 完全不用动。

同一台 Trae 客户端切换账号会覆盖本机 `storage.json`，所以**每导完一个号立刻存进对应 Secret，再切下一个号**。

**设备号冲突（已实测）**：同一客户端切号导出的多个账号会共用同一个 deviceId，而服务端按 `x-device-id`
做「设备今日已签到」幂等，第二个号只会拿到 `9095 当前设备今日已经签到，请明日再来哦～`，
`checked_in` 仍是 `false`（界面上的 100 积分是余额，不是当天到账）。
`lib/state.py` 加载时会自动检测重复的 deviceId，给后一个账号派生同长度、不同末位的纯数字号，
日志里会显示「设备号冲突，已自动派生 4891→4897」。别把设备号留空：不带 `x-device-id` 会返回 `9004 参数错误`。
派生号只用于签到请求头；token 续期有不带设备证明的旧端点兜底，不受影响。

生成 STATE_KEY：

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. 手动触发验证

Actions → `Trae 每日签到` → Run workflow。看 Step Summary 里的表格，确认状态是「签到成功」或「今日已签」，
再确认 `state/credentials.enc` 被自动提交了一次。之后就交给定时任务。

## 定时策略

**一天只跑一次**：`23 4 * * *`（UTC）= 北京时间 **12:23**。错开整点是为了避开 GitHub Actions 的集中排队。

选 12:23 的理由：签到按自然日重置，零点过后就能签；12:23 无论服务端按北京日界还是 UTC 日界重置都已过，且这个时段 GitHub 排队压力较小。GitHub 的 scheduled workflow 在高峰期可能延迟数小时甚至偶尔漏跑，属正常现象，只要当天跑成功就不影响积分。

容错全部收在程序内部，不靠多跑几轮：

| 情况 | 处理 |
| --- | --- |
| 网络超时 / 连接失败 | 同一轮内退避重试最多 3 次（1s / 2s） |
| `HTTP 429`、`5xx` | 同上，有限重试 |
| `9074` 设备指纹或限流 | **刻意不重试**，实测连发会延长惩罚窗口；次日自动重来 |
| 登录态失效 | 自动续期后重试一次 |
| 当天已经签过 | 查到 `checked_in=true` 直接跳过，不会重复领取 |

真遇到漏跑或想立刻补签，在 Actions 里手动点 **Run workflow** 即可。

## 最重要的坑：真实设备号

签到接口会校验 `x-device-id`。**必须是 Trae 客户端真实注册过的设备号**（12~20 位纯数字），
否则一律返回：

```json
{"code": 9074, "message": "当前参与用户太多，请稍后再试"}
```

这句提示是误导性的，跟人数无关，实际是设备指纹没过校验。

| 做法 | 结果 |
| --- | --- |
| 从 `storage.json` 的键 `iCubeAuthInfo://icube-dc:<数字>` 取冒号后的数字 | 可用 |
| 随机 hex / UUID / `telemetry.devDeviceId` | 必然 9074 |
| 走一遍网页 OAuth 登录，随便填个设备号 | 不会把设备注册成可信，照样 9074 |
| 同一设备号配给多个账号 | 第二个起返回 9095（一台设备一天只签一个账号） |

导出脚本会自动做这件事，并在取不到时明确告警。多账号就得多台设备。

## token 轮换与加密状态

Trae 每次续期都会**轮换 refreshToken**，静态 Secret 越刷越失效。处理方式：

1. 各 `TRAE_ACCOUNTS*` Secret 是账号的唯一真相，按编号合并，随时可以增删账号、更新凭证；
2. 每次运行前读 `state/credentials.enc`，把上次轮换出的 accessToken / refreshToken / expiresAt 覆盖进去；
3. 签到结束后用 `STATE_KEY` 派生的 AES-128-CBC + HMAC-SHA256 密钥加密整份状态，写回该文件；
4. workflow 用 `GITHUB_TOKEN` 把这一个加密文件提交回仓库（密文公开可见，但缺 `STATE_KEY` 无法解密）。

客户端 `storage.json` 不带 expiresAt，程序会从 accessToken 的 JWT `exp` 推导（通常 14 天），只在快过期时续期；
否则每轮都拿静态 refreshToken 去续期，容易与活跃的本机客户端撞上轮换冲突，被打回 `10101 refresh token is not matched to the client`。

所以 `STATE_KEY` 不能中途更换。真换了，状态文件解不开，脚本会回退到 Secret 的初始凭证并给出告警，
此时重新跑一次 `tools/export_credentials.py` 更新对应编号的账号 Secret 即可。

## 错误码

| code / 情况 | 含义 | 脚本行为 |
| --- | --- | --- |
| `0` | 领取成功 | 回查确认到账，否则标记「成功但积分未到账」 |
| `9095` | 本设备今日已签（多账号共用 deviceId 时后者会撞） | 归为已签跳过；加载时自动派生设备号避免冲突 |
| `9004` | 订单参数错误（常见于没带 `x-device-id`） | 归为已签跳过，但日志带服务端原文，据此排查设备号是否为空 |
| `9074` | 设备指纹没过或服务端限流 | 不做当场重试（连发会延长惩罚），次日自动重来 |
| `1001` / `1002` / `401` / `403` | 登录态失效 | 自动续期后重试一次 |
| `20405` | 新版续期缺设备证明 | 自动走设备签名端点，失败再退旧端点 |
| `HTTP 429/5xx` | 服务端排队 | 同一轮内退避重试最多 3 次 |
| 活动 `enable=false` | 签到入口未开放 | 标记「活动未开启」，不算失败 |

## 目录结构

```
.
├── .github/workflows/
│   ├── checkin.yml          定时签到 + 状态写回 + 运行报告
│   └── validate.yml         语法 / 单测 / YAML / 泄漏扫描
├── lib/
│   ├── crypto.py            tc 解密、AES-128-CBC + HMAC-SHA256 状态加密、P-256 设备签名
│   ├── trae_api.py          签到接口、请求头、token 续期
│   └── state.py             凭证加载、轮换合并、状态持久化
├── tools/
│   ├── export_credentials.py  本机导出完整登录态（推荐）
│   └── login.py               网页验证码登录（备选）
├── tests/test_offline.py   离线单测，不联网不认证
├── checkin.py              云端主程序
├── state/credentials.enc   运行后自动生成的加密状态
└── result.json             每次运行的结果汇总（不提交）
```

## 本地调试

```bash
# 离线单测
python -m unittest discover -s tests -v

# 用真实凭证只查状态、不领取、不写状态
TRAE_ACCOUNTS='<导出的那行 JSON>' STATE_KEY='<随机串>' python checkin.py --dry-run --no-save

# 真跑一次
TRAE_ACCOUNTS='<导出的那行 JSON>' STATE_KEY='<随机串>' python checkin.py
```

Windows 下用 `set` 或 PowerShell 的 `$env:` 设置环境变量，别把凭证写进文件。

## 常见问题

| 问题 | 处理 |
| --- | --- |
| 定时任务突然不跑了 | 仓库 60 天无任何活动，GitHub 会自动停用 scheduled workflow，随便推个 commit 即可恢复 |
| Actions 额度 | 公开仓库标准 runner 不限分钟数；每天 1 次、每次约 1 分钟，成本为 0 |
| 定时那一轮延迟或漏跑 | GitHub 高峰期常见；当天晚点跑成功也算数，急着补就手动 Run workflow |
| 一直 9074 | 九成是设备号不是客户端真实注册值；用导出脚本重新取，别自己编 |
| 第二个号显示「今日已签」但积分没涨 | 看日志里的 code 和原文：`9095` 是设备维度已签，不是账号到账。确认两个账号的设备尾号不同 |
| 一直报登录态失效 | refreshToken 已被别的客户端用掉（轮换冲突）。重新导出凭证，且导出后别在别处同时用旧登录态续期 |
| 海外出口 IP 被风控 | Actions 出口在美国，接口变动时可改成自建 runner 或换 Cloudflare Worker，本项目接口层已隔离在 `lib/trae_api.py` |
| 想加账号 | 新建下一个编号的 `TRAE_ACCOUNTS_N` Secret；别改已有 Secret（Secret 读不出旧值）。状态文件按 userId + deviceId 自动匹配 |

## 安全说明（公开仓库）

仓库公开是为了让 GitHub Actions 标准 runner 不限分钟数。**公开等于以下东西全世界可见**，配置时要清楚：

| 公开可见 | 内容 | 防护 |
| --- | --- | --- |
| 全部源码与提交历史 | 接口端点、设备头构造、业务逻辑 | 历史已收敛为单个初始快照，无 token、私钥、PAT、真实账号标识 |
| Actions 运行日志 | 账号数、设备号**尾号**、签到状态、积分余额 | 不打印完整 userId / 设备号 / token |
| `result.json` artifact | 运行报告 | `userId` 只留尾号（`***1234`），不含任何凭据字段 |
| `state/credentials.enc` | 轮换后的登录态**密文** | AES-128-CBC + HMAC-SHA256；密钥由 `STATE_KEY` 派生，只存在 Secrets |
| 仓库 Settings 里的 Secret 名 | `TRAE_ACCOUNTS*`、`STATE_KEY` 等名称 | 值永远不公开、不进日志、fork 拿不到 |

必须守住的红线：

- **`STATE_KEY` 绝不能泄露、改写或删除**。它是 256 bit 随机串，只存在于 GitHub Secret；一旦泄露，公开的密文就能被解开。
- 不要把任何 `TRAE_ACCOUNTS*` 的内容写进 commit、Issue、Discussion、日志或任何公开位置。
- 不要在公开仓库接受 fork 的 PR 触发 CI：`validate.yml` 刻意不监听 `pull_request`，避免未审核代码在 runner 上执行。
- fork 本仓库不会继承 Secrets，别人 fork 过去也签不了你的号；但 fork 里的 `state/credentials.enc` 是历史密文，仍依赖 `STATE_KEY` 保密。
- Actions 会自动把 Secrets 在日志里打码，脚本本身也不主动输出凭据。

## 声明

非官方接口实现，接口随时可能变更，账号风险自行承担。只用于自己账号的每日积分领取。
参考来源见 [NOTICE.md](NOTICE.md)。
