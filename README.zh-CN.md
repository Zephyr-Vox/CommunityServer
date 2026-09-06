# ZephyrVox CommunityServer

[English](README.md) | **中文**

基于 Go 1.26、Echo v5 和 SQLite 的单进程语音社区服务器，提供账号管理、
数据库驱动的 RBAC、频道、WebSocket 实时状态和有界 UDP 语音中继。

## 启动

```sh
go run ./cmd/zephyrd
```

首次启动会生成 `config/zephyr.toml`、`./data/zephyr.db` 和本地对象存储，
并在日志中打印一次性 owner 激活码。默认配置使用自动生成的自签名 HTTPS：

```sh
curl -k -X POST https://localhost:8745/api/v0/admin/activate \
  -H 'Content-Type: application/json' \
  -d '{"code":"ACTIVATION_CODE","username":"boss","password":"secret123"}'
```

本地明文调试时，把 `server.tls_mode` 设为 `"off"`，并使用
`http://localhost:8745`。这也会选择明文语音会话。

## 当前能力

- 首 owner 激活、开放/邀请码注册和可轮换的认证会话；
- 数据库角色、binding、ACL 和 moderation；
- group、永久 text/announcement channel 和临时 voice channel；
- 鉴权状态快照、可回放的 WebSocket 事件和 presence；
- 有界 UDP 语音 session、中继扇出、负载控制和诊断；
- 本地对象存储和 JPEG 头像处理。

## API 入口

所有控制面路由使用 `/api/v0`。公开发现接口是
`GET /api/v0/metadata`；鉴权客户端使用 `/api/v0/auth/login`、
`GET /api/v0/state/snapshot` 和 `GET /api/v0/ws`。语音 join/leave 走 HTTP，
UDP 只承载语音媒体和 heartbeat。

JSON 响应统一为 `{"code":0,"message":"","data":...}`；`204` 无 body。
进入顺序化 mutation 的修改使用幂等键；带版本的资源使用强 ETag。

## 配置

首次生成的配置包含 HTTP 监听端口（`8745`）、UDP 语音端口（`8746`）、
对外语音地址、TLS 模式、SQLite 路径、对象存储路径、注册模式、头像限制、
语音限制和日志设置。请妥善保护 JWT secret 和 TLS 私钥。

## 开发

```sh
go build ./...
go vet ./...
go test -race ./...
sqlc generate
```

测试位于 `test/`，并镜像 production package。按领域拆分的详细本地设计说明
位于 `spec/`；该目录按约定不作为发布文档纳入版本库。
