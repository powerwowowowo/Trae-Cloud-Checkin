# 说明与致谢

本项目的代码为独立实现，接口信息来自公开社区讨论与开源项目的逆向结论，未使用任何官方私有文档，也不包含任何账号凭据。

## 参考过的公开资料

| 项目 / 资料 | 借鉴的点 |
| --- | --- |
| `L0NE-6/Trae-AutoCheckin` | `/trae/api/v2/ug/checkin_credits/*` 端点、`req_source` 请求体、9074/9004/9095 业务码、新版 ExchangeToken 需要 ECDSA 设备证明、refreshToken 轮换必须持久化 |
| `xz0609/trae-work-checkin-ql` | 设备指纹头集合、`x-device-id` 必须是客户端真实注册值、`api.trae.com.cn` 旧续期端点 |
| `iicookies/auto-checkin` | 最小请求头集合、Cloud-IDE-JWT 前缀、JWT payload 里取 userId |
| `Maquer/trae-signin` | GitHub Actions 定时签到的组织方式、真实设备号与 9095（一台设备一天一个账号）说明、网页登录回调流程 |
| `ella-ai-labs/trae-daily-checkin` | storage.json 的 tc 加密结构（SHA-512 派生 + AES-128-CBC + HMAC 前缀） |
| TRAE 官方中文社区「TraeWork每日自动签到」帖 | status / claim 端点与幂等行为的公开描述 |

## 使用边界

- 这是非官方调用方式，接口随时可能变更；接口变动时以仓库里的 `lib/trae_api.py` 为唯一适配点。
- 只用于自己账号的每日积分领取，不做批量注册、不做额度转售、不绕过付费。
- 使用即表示自行承担账号风险；如平台明确禁止自动化签到，请停止使用并删除本仓库的 Secrets。

## 许可证

本项目代码采用 MIT 许可证，见 `LICENSE`。上述参考项目各有自己的许可证，本项目未复制其源码文件。
