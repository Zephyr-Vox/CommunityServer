CREATE TABLE users (
    id            INTEGER PRIMARY KEY,               -- 63-bit snowflake ID
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,                  -- argon2id encoded hash
    nickname      TEXT    NOT NULL,
    avatar        TEXT,                              -- avatar URL/path; NULL = default
    auth_version  INTEGER NOT NULL DEFAULT 0,        -- bumped to revoke all issued tokens
    banned_at     INTEGER,                           -- NULL = active; set = soft ban
    last_login_at INTEGER,                           -- last successful login
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
) STRICT;

CREATE TABLE user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    TEXT    NOT NULL,                        -- role name defined in roles.yaml
    PRIMARY KEY (user_id, role)
) STRICT;

CREATE TABLE sessions (
    id              INTEGER PRIMARY KEY,             -- 63-bit snowflake ID
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       TEXT    NOT NULL,                -- client-provided device identifier
    token_hash      TEXT    NOT NULL UNIQUE,         -- SHA-256 of the current refresh token
    prev_token_hash TEXT,                            -- SHA-256 of the previous token; enables reuse detection
    expires_at      INTEGER NOT NULL,
    last_used_at    INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    UNIQUE (user_id, device_id)                      -- one session row per device; refresh updates in place
) STRICT;

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE invites (
    id         INTEGER PRIMARY KEY,                  -- 63-bit snowflake ID
    code_hash  TEXT    NOT NULL UNIQUE,              -- SHA-256; plaintext code returned once at creation
    role       TEXT    NOT NULL DEFAULT 'member',    -- role granted when redeemed
    uses_left  INTEGER NOT NULL DEFAULT 1 CHECK (uses_left >= 0),
    expires_at INTEGER,                              -- NULL = never expires
    created_by INTEGER REFERENCES users(id),         -- admin who created it; NULL = system
    created_at INTEGER NOT NULL
) STRICT;
