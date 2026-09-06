# ZephyrVox CommunityServer

**English** | [中文](README.zh-CN.md)

Single-process voice-community server built with Go 1.26, Echo v5 and SQLite.
It provides account management, database-backed RBAC, channels, WebSocket
realtime state and a bounded UDP voice relay.

## Start

```sh
go run ./cmd/zephyrd
```

The first start creates `config/zephyr.toml`, `./data/zephyr.db` and the local
object store. It prints a one-time owner activation code. The default config
uses HTTPS with an auto-generated self-signed certificate:

```sh
curl -k -X POST https://localhost:8745/api/v0/admin/activate \
  -H 'Content-Type: application/json' \
  -d '{"code":"ACTIVATION_CODE","username":"boss","password":"secret123"}'
```

For local plaintext development, set `server.tls_mode = "off"` and use
`http://localhost:8745`. This also selects plaintext voice sessions.

## Current capabilities

- first-owner activation, open/invite registration and rotating auth sessions;
- database-backed roles, bindings, ACLs and moderation;
- groups, permanent text/announcement channels and temporary voice channels;
- authenticated state snapshots, replayable WebSocket events and presence;
- bounded UDP voice sessions, relay fanout, load control and diagnostics;
- local object storage and JPEG avatar processing.

## API entry points

All control-plane routes use `/api/v0`. Discovery is public at
`GET /api/v0/metadata`; authenticated clients use `/api/v0/auth/login`,
`GET /api/v0/state/snapshot` and `GET /api/v0/ws`. Voice join/leave is handled
by HTTP; UDP carries only voice media and heartbeats.

JSON responses use `{"code":0,"message":"","data":...}`. `204` responses
have no body. Sequenced mutations use idempotency keys; versioned resources use
strong ETags.

## Configuration

The generated configuration contains the HTTP listener (`8745`), UDP voice
listener (`8746`), advertised voice host, TLS mode, SQLite path, object-store
path, registration mode, avatar limits, voice limits and log settings. Keep the
JWT secret and TLS private key private.

## Development

```sh
go build ./...
go vet ./...
go test -race ./...
sqlc generate
```

Tests live under `test/` and mirror production packages. Detailed, local design
notes are split by domain under `spec/`; that directory is intentionally not
tracked as release documentation.
