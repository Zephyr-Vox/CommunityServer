# Repository Guidelines

## Project Structure & Module Organization

ZephyrVox CommunityServer is a Go 1.26.5 + Echo v5 + SQLite voice server.

- `internal/` — production code, organized by domain: `auth/`, `store/`, `rbac/`, `cache/`, `config/`, `validation/`, `snowflake/`, `logging/`, `protocol/`.
- `internal/protocol/` — the voice wire protocol domain: UDP datagram codec, AEAD/HKDF crypto, replay window, per-session rate limit, channel registry, in-memory session manager and UDP server. It has no Echo/HTTP dependency; HTTP/control-plane adapters belong to the application layers.
- `internal/db/` — sqlc-generated data access (`*.sql.go`); never edit generated files by hand. The only hand-maintained files are `schema.sql` and `schema.go` (the embedded schema).
- `internal/db/schema.sql` + `db/queries/` — SQL sources. Edit these, then run `sqlc generate`.
- `VERSION` at the module root — plain version text, embedded into the binary by the root `version` package and printed after the startup banner.
- `test/` — all tests, one subdirectory per package (`test/auth/`, `test/store/`). Business directories contain no `_test.go`.
- `spec/spec.md` — local design specs. Gitignored; never commit.

## Architecture Invariants

- One process instance is exactly one community server. There is no tenant or multi-server concept; "creating a server" means first-time initialization/bootstrap of this backend process. Do not introduce a `servers` table or tenant scoping.
- `owner` is the only immutable built-in role: globally unique, always grants `*`, bypasses channel/group ACLs, and is protected by last-owner rules. It may be transferred by the current owner; the previous owner is demoted to `member`.
- A user may have multiple active WS control connections, one per client. The control plane is online while at least one WS is alive. A user has at most one voice binding and one logical UDP voice session; UDP expiry clears only that voice binding/session and keeps WS connections and presence alive. If the WS that owns voice closes, the server immediately deactivates its UDP session and conditionally clears that voice binding; other WS connections remain active. Presence becomes offline only after the last WS closes.
- A user has at most one active voice-channel membership and one UDP voice session. Joining a voice channel allocates or reuses that session. Text channels have no server-side membership or active pointer; the focused text channel is purely client UI state and is never persisted or broadcast.
- Only `voice` channels can be temporary. `text` and `announcement` channels are always permanent; a temporary voice channel carries text chat as a secondary capability and is deleted when its last voice member leaves.
- The server pushes every event for channels visible to a WS connection; there are no per-channel message subscriptions or server-side focus state. Clients decide locally which events affect their current UI focus.
- Presence is server-global user status (`online` / `dnd` / `afk` / `offline` / `invisible`) plus optional user activity with user-controlled privacy. Channel membership is a separate event stream and is filtered by channel ACL visibility.
- State/control events must be delivered immediately in `seq` order. Message events are lower priority and may later be coalesced into batches and pushed asynchronously; batching must never delay state/control events.
- Voice overload control uses fixed hard upper bounds as safety caps plus elastic soft limits adjusted by server load (fast decrease, slow recovery). Hard limits are startup configuration values with defaults and are optional to specify; the protocol package receives them from the application layer.
- Role definitions and role assignments live in the database; there is no runtime roles.yaml. On first initialization the built-in roles (`owner`, `admin`, `member`) are seeded into the database.
- Roles are defined once at server scope. Every role has an immutable key and an editable display name; `owner` is mandatory, always grants `*`, and only its display name may change.
- Group/channel permission configs either inherit the nearest non-inheriting parent config or store a local copied snapshot that can be customized. Once a local snapshot exists, parent changes no longer propagate. Permission edits must be validated so the owner can always reset/repair the permission system.
- Channels have a configurable capacity. A full channel rejects join; until real capacity limits are chosen, the default is the maximum value.
- A metadata endpoint owns UDP voice endpoint discovery and exposes a single protocol version; the HTTP API and WS protocol are part of that one version, not separately versioned. Clients check the version themselves. The server never falls back to older protocol versions.
- Voice diagnostics (`voice.stats` events) are part of the realtime protocol and are scoped to the user's own session/channel.
- StateStore uses versioned state snapshots rather than holding a global write lock while serializing snapshots.
- State synchronization is pluggable behind one sync-strategy interface. v1 implements full snapshot sync; visibility-aware fragment digest sync is the preferred future optimization and must not require wire-protocol breaking changes when introduced.
- Server metrics are exposed through a metrics endpoint guarded by a `server.metrics` permission; per-user voice diagnostics use scoped `voice.stats` events instead.

## Build, Test, and Development Commands

- `sqlc generate` — regenerate data access code after SQL changes.
- `go build ./...` — compile everything.
- `go vet ./...` — static checks.
- `gofmt -w <files>` — format code; Go uses standard tab indentation.
- `go test -race ./...` — full suite with the race detector; must pass before any commit.
- `go mod tidy` — after adding dependencies (requires network).

## Coding Style & Naming Conventions

- Standard Go: tabs, gofmt, lowercase file names.
- Prefer modern stdlib idioms: `slices.Contains`/`Sort`, `sync.WaitGroup.Go`, `errors.AsType`.
- Core packages (`rbac`, `snowflake`, `cache`, `logging`) must not import Echo or config; adapters live in `internal/rbac/echo` and `internal/validation`.
- Logging uses `log/slog` through `internal/logging` only: human-readable text with optional ANSI colors, a rotating zip file sink, and fanout. No structured logging and no third-party logging libraries.
- Every application log call carries a `module` attr (or derives from a logger that sets one). Domain packages do not log directly: they return errors, and boundary layers (`cmd`, the HTTP request logger, the API error handler) record them.
- All IDs are 63-bit snowflake IDs; timestamps are Unix milliseconds (UTC); SQL comments are English.
- Group helpers by what they serve (e.g., `token.go`, `middleware.go`); no generic `utils` packages.
- Request/response DTOs go in `request.go` / `response.go`; request-shape validation uses struct tags through `internal/validation`.
- HTTP handlers all live in the package's `handlers.go`; services/managers stay in their feature files. Handlers that need identity receive the principal via `rbacecho.WithPrincipal`; never re-check auth inside a handler.

## API Response Convention

- Every JSON response is an envelope: `{"code": 0, "message": "", "data": ...}`. `code` 0 with an empty `message` means success and `data` carries the DTO; any non-zero `code` is a business error, `message` explains it, `data` is null.
- 204 responses have no body and are not wrapped.
- There is no endpoint-wide global error-code table. Every handler numbers its own business errors from 1; codes may repeat across endpoints, so clients switch on (endpoint, code), never on message strings. The constants are declared locally inside each handler factory, next to their `// Errors:` doc block. Request-level and middleware errors are global and shared by every endpoint, in the 1000 block of `internal/api`: `1000` invalid request parameters (400, field messages in `data.fields`), `1001` malformed request (400), `1002` unauthorized (401), `1003` forbidden (403), `1004` not found (404), `1005` method not allowed (405), `1006` payload too large (413), `1007` unsupported media type (415), `1008` rate limited (429), `1009` internal (500+). Endpoint codes stay in 1..999 so the two ranges never collide.
- Every handler doc comment lists its possible error codes in this fixed format:
  `// Errors:` followed by one `//   - <code> <short reason>: <one-line explanation>` per error; shared 1000-block errors are listed with their code.
- Handlers never build ad-hoc maps for response data or request payloads: use DTOs from `response.go` / `request.go` (per package). Binding and validation go through `api.Bind(c, &req)`: validation failures render as global code `1000` with the uniform message `invalid request parameters` and `data.fields` as a `field -> message` map (field names identify the location; there are no per-field codes); malformed bodies render as global code `1001`. Success is emitted via `api.OK`/`api.NoContent`, errors via `api.NewError`, and `api.ErrorHandler` must be installed on the Echo instance.

## Testing Guidelines

- Standard library `testing` only; no framework.
- Mirror package paths: `test/auth/register_test.go` tests `internal/auth`.
- Concurrency correctness is load-bearing (snowflake, cache singleflight, invite redemption), so race-sensitive tests are mandatory, not optional.
- Full suite must be green before presenting a commit for review.

## Commit & Pull Request Guidelines

- Conventional Commits, per history: `feat(auth): ...`, `refactor(store): ...`, `chore: ...`.
- One logical change per commit; no manual line wrapping inside a paragraph.
- Do not commit `spec/` or generated config files.
- No PR workflow; changes land directly on `main` after review.
- **Agent rule:** stop after implementation and tests, present the proposed commit message, and wait for approval before committing.

## Environment Notes (Codex)

- Git writes and network access (`go get`, `go mod tidy`) require sandbox escalation.
- Use `GOCACHE=/tmp/gocache-codex` when the default Go cache is blocked.
