# ZephyrVox CommunityServer

**English** | [中文](README.zh-CN.md)

Single-server community edition of a lightweight voice-community server, in the spirit of TeamSpeak / Discord. Built with Go 1.26, Echo v5, and SQLite (pure-Go driver).

## Features

- Account bootstrap: first-admin activation code, open or invite-based registration
- Authentication: argon2id passwords, short-lived JWT access tokens, rotating refresh sessions with reuse detection
- Role-based authorization: permissions configured in `roles.yaml`, enforced per route
- User management: list/detail, profile, roles, password reset, kick, ban/unban, hard delete
- Invite management: create / list / delete invite codes
- Presence: lightweight in-memory heartbeat-based online status
- Local object storage: disk-backed files with SQLite metadata and MIME detection
- Avatars: upload/reset with unified JPEG transcoding (any decodable image in, 256×256 JPEG out), served from a public route

## Quick Start

```sh
go run ./cmd/zephyrd
```

The first start generates `config/zephyr.toml` and `config/roles.yaml` automatically and opens the SQLite database configured in `server.db_path` (default `./data/zephyr.db`). When no administrator exists yet, the startup log prints a one-time activation code:

```sh
INFO first admin activation required code: ABC234...
```

Activate the first admin. The default config serves HTTPS with an
auto-generated self-signed certificate, so local curl calls need `-k`:

```sh
curl -k -X POST https://localhost:8745/api/v0/admin/activate \
  -H 'Content-Type: application/json' \
  -d '{"code":"ABC234...","username":"boss","password":"secret123"}'
```

For plaintext local testing, set `server.tls_mode = "off"` in
`config/zephyr.toml` and use `http://localhost:8745` instead.

Then sign in with the same credentials at `POST /api/v0/auth/login`.

Flags:

```sh
zephyrd -config config/zephyr.toml -roles config/roles.yaml
```

## Configuration

`config/zephyr.toml` is generated on first start (0600, it contains the JWT secret):

| Key | Default | Description |
|---|---|---|
| `jwt_secret` | random 256-bit value as 64 hex characters | HS256 signing secret for access tokens |
| `auth.access_token_ttl` | `15m` | access token lifetime |
| `auth.refresh_token_ttl` | `720h` | refresh session sliding lifetime |
| `auth.login_rate_limit` | `10` | login/activate attempts per minute per IP |
| `auth.registration_mode` | `invite` | `open` or `invite` |
| `server.host` | `0.0.0.0` | HTTP listen host |
| `server.http_port` | `8745` | HTTP/REST listener port |
| `server.voice_port` | `8746` | reserved for the future voice channel |
| `server.db_path` | `./data/zephyr.db` | SQLite database file |
| `server.tls_mode` | `required` | TLS mode: `off` or `required`; `required` auto-generates a self-signed certificate |
| `storage.base_dir` | `./data/objects` | local object storage root |
| `avatar.max_upload_size` | `10485760` | avatar upload size limit in bytes (10 MiB) |
| `avatar.max_dimension` | `4096` | source image max side in pixels; rejects decompression bombs |
| `avatar.target_size` | `256` | output avatar side in pixels (square) |
| `avatar.quality` | `85` | JPEG quality, 0-100 |
| `log.level` | `info` | minimum log level: `debug`, `info`, `warn`, `error` |
| `log.path` | `./data/logs` | log directory (live `zephyr.log` + archives); empty = console only |
| `log.archive_keep` | `7` | keep the newest N archives; `0` = no archives; `-1` = keep all |

Console logs are human-readable colored lines on stdout. When `log.path` is set (the default), the same lines are also written to `zephyr.log` there; every 7 days the accumulated file is merged into a dated `.zip` archive (`zephyr-YYYY-MM-DD-NN.zip`) and `log.archive_keep` prunes old archives.

`config/roles.yaml` defines roles and their permissions. The generated default has:

- `admin`: `["*"]`
- `member`: `["voice:join"]`

Available permissions: `voice:join`, `user:read`, `user:create`, `user:update`, `user:delete`, `user:kick`, `invite:manage`.

## API Conventions

Every JSON response is an envelope:

```json
{"code": 0, "message": "", "data": {...}}
```

- `code` 0 with empty `message` means success; `data` carries the DTO.
- Endpoint-specific business codes run from 1 (per endpoint, listed in each handler's doc comment). Clients branch on `(endpoint, code)`.
- Shared global codes: `1000` invalid request parameters (field messages in `data.fields`), `1001` malformed request, `1002` unauthorized, `1003` forbidden, `1004` not found, `1005` method not allowed, `1006` payload too large, `1007` unsupported media type, `1008` rate limited, `1009` internal.
- `204` responses have no body. Binary object downloads are raw bytes, not envelopes.

## API Overview

All paths are prefixed with `/api/v0`.

| Area | Endpoints |
|---|---|
| Auth | `GET /auth/status`, `POST /auth/register`, `POST /admin/activate`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout` |
| Self | `GET /auth/me`, `PATCH /me`, `POST /me/avatar`, `DELETE /me/avatar`, `POST /me/password` |
| Users | `GET /users`, `GET /users/:id`, `PATCH /users/:id`, `PUT /users/:id/roles`, `POST /users/:id/password`, `POST /users/:id/kick`, `POST /users/:id/ban`, `POST /users/:id/unban`, `DELETE /users/:id` |
| Invites | `GET /admin/invites`, `POST /admin/invites`, `DELETE /admin/invites/:id` |
| Presence | `POST /presence/heartbeat`, `GET /presence` |

Avatar endpoints: `POST /api/v0/me/avatar` accepts a multipart `file` field (any format Go can decode) and stores a uniformly transcoded JPEG; `DELETE /api/v0/me/avatar` resets to the default. The image is served publicly at `GET /avatar/:file` — note this route sits outside the `/api/v0` prefix. The `avatar` field in user DTOs carries the bare object name (e.g. `12345.jpg`); clients build the full URL by joining it with the public prefix, currently the fixed route `/avatar/` (e.g. `/avatar/12345.jpg`).

## Development

```sh
go build ./...          # compile
go vet ./...            # static checks
gofmt -w <files>        # format (Go tabs)
go test -race ./...     # full suite with race detector
sqlc generate           # regenerate data access after SQL changes
```

Business packages contain no `_test.go`; tests live under `test/` mirroring package paths. Tests that bind real ports (graceful shutdown) require permission to open local sockets.

There is no migration system yet: the schema is applied idempotently at startup, and schema changes during development require deleting the database file.
