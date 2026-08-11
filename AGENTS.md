# Repository Guidelines

## Project Structure & Module Organization

ZephyrVox CommunityServer is a Go 1.26.5 + Echo v5 + SQLite voice server.

- `internal/` — production code, organized by domain: `auth/`, `store/`, `rbac/`, `cache/`, `config/`, `validation/`, `snowflake/`.
- `internal/db/` — sqlc-generated data access. Never edit by hand.
- `db/schema.sql` + `db/queries/` — SQL sources. Edit these, then run `sqlc generate`.
- `test/` — all tests, one subdirectory per package (`test/auth/`, `test/store/`). Business directories contain no `_test.go`.
- `spec/spec.md` — local design specs. Gitignored; never commit.

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
- Core packages (`rbac`, `snowflake`, `cache`) must not import Echo or config; adapters live in `internal/rbac/echo` and `internal/validation`.
- All IDs are 63-bit snowflake IDs; timestamps are Unix milliseconds (UTC); SQL comments are English.
- Group helpers by what they serve (e.g., `token.go`, `middleware.go`); no generic `utils` packages.
- Request/response DTOs go in `request.go` / `response.go`; request-shape validation uses struct tags through `internal/validation`.

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
