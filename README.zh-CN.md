# ZephyrVox CommunityServer

[English](README.md) | **中文**

轻量级语音社区服务器的单机社区版，定位类似 TeamSpeak / Discord。基于 Go 1.26、Echo v5 和 SQLite（纯 Go 驱动）构建。

## 功能

- 账号引导：首 owner 激活码、开放注册 / 邀请码注册
- 认证：argon2id 密码、短时效 JWT access token、可轮换且带重用检测的 refresh session
- 数据库驱动的 RBAC：内置角色、scope binding、ACL 和权限配置
- 用户管理：列表/详情、资料、重置密码、踢下线、封禁/解封、硬删除
- 邀请码管理：创建 / 列表 / 删除
- presence：轻量内存心跳在线状态
- 实时协议模型：每个客户端独立维护一条 WS 控制连接；每个账号最多一个逻辑 UDP 语音会话
- 本地对象存储：磁盘文件 + SQLite 元数据 + MIME 探测
- 头像：上传/重置 + 统一 JPEG 转码（任意可解码图片进，256×256 JPEG 出），公开路由提供读取

## 实时连接模型

目标实时协议将控制面和语音面分开：

- 一个用户可以同时保持多条 WS 控制连接，每个客户端一条；每条连接都接收自己可见的服务器和频道状态。
- 一个账号最多一个 voice membership 和一个逻辑 UDP voice session。新的语音 join 可以替换旧语音 session，但不会关闭旧客户端的 WS 控制连接。
- UDP 语音失败时，WS 控制连接和 presence 保持正常。服务端通过 `voice.disconnected` 或 `voice.revoked` 通知客户端，客户端可以重试 join，或提示语音服务暂不可用。
- 拥有语音的 WS 关闭时，服务端立即停止它绑定的 UDP session，只删除该 voice membership；其他 WS 继续可用。
- 只有用户最后一条 WS 控制连接关闭后，presence 才变为 offline。

这是目标协议模型。下面的 HTTP API 清单仍反映当前仓库已经实现的路由。

## 快速开始

```sh
go run ./cmd/zephyrd
```

首次启动会自动生成 `config/zephyr.toml`，并按 `server.db_path`（默认 `./data/zephyr.db`）打开数据库。数据库会 seed `owner`、`admin`、`member`、根权限配置、installation state 和公开公告频道；首 owner 激活前，启动日志会打印一次性激活码：

```sh
INFO first owner activation required code: ABC234...
```

激活首 owner。默认配置使用 HTTPS 并提供自动生成的自签证书，本地 curl 需要加 `-k`：

```sh
curl -k -X POST https://localhost:8745/api/v0/admin/activate \
  -H 'Content-Type: application/json' \
  -d '{"code":"ABC234...","username":"boss","password":"secret123"}'
```

如果只想在本地用明文 HTTP 调试，把 `config/zephyr.toml` 里的
`server.tls_mode` 改成 `"off"`，再把上面的地址换回 `http://localhost:8745`。

然后用同一账号调用 `POST /api/v0/auth/login` 登录。

命令行参数：

```sh
zephyrd -config config/zephyr.toml
```

## 配置

`config/zephyr.toml` 首次启动自动生成（0600 权限，内含 JWT 密钥）：

| 键 | 默认值 | 说明 |
|---|---|---|
| `jwt_secret` | 随机 256 位（64 个十六进制字符） | access token 的 HS256 签名密钥 |
| `auth.access_token_ttl` | `15m` | access token 有效期 |
| `auth.refresh_token_ttl` | `720h` | refresh session 滑动有效期 |
| `auth.login_rate_limit` | `10` | 每 IP 每分钟 login/activate 次数 |
| `auth.registration_mode` | `invite` | `open` 或 `invite` |
| `server.host` | `0.0.0.0` | HTTP 监听地址 |
| `server.http_port` | `8745` | HTTP/REST 监听端口 |
| `server.voice_port` | `8746` | 预留的语音通道端口 |
| `server.db_path` | `./data/zephyr.db` | SQLite 数据库文件 |
| `server.tls_mode` | `required` | TLS 模式：`off` 或 `required`；`required` 会自动生成自签证书 |
| `storage.base_dir` | `./data/objects` | 本地对象存储根目录 |
| `avatar.max_upload_size` | `10485760` | 头像上传大小上限（字节，10 MiB） |
| `avatar.max_dimension` | `4096` | 源图最大边长（像素），防止解码放大攻击 |
| `avatar.target_size` | `256` | 输出头像边长（像素），正方形 |
| `avatar.quality` | `85` | JPEG 质量，0-100 |
| `log.level` | `info` | 最低日志级别：`debug`、`info`、`warn`、`error` |
| `log.path` | `./data/logs` | 日志目录（实时 `zephyr.log` + 归档）；空串 = 仅控制台 |
| `log.archive_keep` | `7` | 保留最近 N 个归档；`0` = 不保留归档；`-1` = 永久保留 |

控制台日志是输出到 stdout 的人类可读彩色日志。配置 `log.path`（默认）时，同一份日志也会写入该目录的 `zephyr.log`；每 7 天将累积文件合并归档为带日期的 `.zip`（`zephyr-YYYY-MM-DD-NN.zip`），并由 `log.archive_keep` 清理旧归档。

RBAC 持久化在 SQLite 中。`owner` 全局唯一并始终授予 `*`；`admin` 和 `member` 为 seed 的内置角色。根权限配置给 admin 授予 server/user/invite/group/channel/moderation 权限，给 member 授予 `channel.create_temporary`。角色、binding、ACL、本地权限配置快照和 mute 都由数据库外键及 scope 唯一约束保护。

## API 约定

所有 JSON 响应统一信封：

```json
{"code": 0, "message": "", "data": {...}}
```

- `code` 为 0 且 `message` 为空表示成功，`data` 携带 DTO。
- 接口级业务码从 1 开始（每个接口独立编号，见各 handler 文档注释），前端按 `(endpoint, code)` 分支。
- 共享全局码：`1000` 参数校验失败（字段消息在 `data.fields`）、`1001` 请求格式错误、`1002` 未授权、`1003` 无权限、`1004` 不存在、`1005` 方法不允许、`1006` 请求体过大、`1007` 不支持的媒体类型、`1008` 限流、`1009` 内部错误。
- `204` 响应无 body；对象下载是原始二进制，不走信封。

## API 一览

所有路径前缀为 `/api/v0`。

| 区域 | 接口 |
|---|---|
| 认证 | `GET /auth/status`、`POST /auth/register`、`POST /admin/activate`、`POST /auth/login`、`POST /auth/refresh`、`POST /auth/logout` |
| 自我管理 | `GET /auth/me`、`PATCH /me`、`POST /me/avatar`、`DELETE /me/avatar`、`POST /me/password` |
| 用户管理 | `GET /users`、`GET /users/:id`、`PATCH /users/:id`、`POST /users/:id/password`、`POST /users/:id/kick`、`POST /users/:id/ban`、`POST /users/:id/unban`、`DELETE /users/:id` |
| RBAC | `GET /rbac/roles`、`POST /rbac/roles`、`PATCH /rbac/roles/:key`、`DELETE /rbac/roles/:key`、`GET/POST/DELETE /rbac/bindings`、`GET/PUT /rbac/config`、`POST /rbac/config/reset`、`POST /owner/transfer` |
| 邀请码 | `GET /admin/invites`、`POST /admin/invites`、`DELETE /admin/invites/:id` |
| Presence | `POST /presence/heartbeat`、`GET /presence` |

头像接口：`POST /api/v0/me/avatar` 接收 multipart 的 `file` 字段（任意 Go 可解码的图片格式），统一转码为 JPEG 存储；`DELETE /api/v0/me/avatar` 重置为默认头像。图片通过公开路由 `GET /avatar/:file` 读取——注意该路由不在 `/api/v0` 前缀下。用户 DTO 中的 `avatar` 字段携带裸对象名（如 `12345.jpg`）；客户端拼接公开前缀得到完整 URL，当前前缀固定为 `/avatar/`（如 `/avatar/12345.jpg`）。

## 开发

```sh
go build ./...          # 编译
go vet ./...            # 静态检查
gofmt -w <files>        # 格式化（Go 使用 Tab）
go test -race ./...     # 全量测试（带 race detector）
sqlc generate           # 修改 SQL 后重新生成数据访问代码
```

业务包内不放置 `_test.go`，测试统一放在 `test/` 下并镜像包路径。绑定真实端口的测试（优雅关闭）需要允许打开本地 socket 的权限。

目前还没有迁移系统：schema 启动时幂等应用，开发期修改 schema 需要删除数据库文件。
