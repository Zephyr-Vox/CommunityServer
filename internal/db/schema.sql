-- Idempotent development schema. There is no migration layer yet: when this
-- layout changes during development, delete the database file and recreate it.

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY CHECK (id > 0),
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    nickname      TEXT    NOT NULL,
    avatar        TEXT,
    auth_version  INTEGER NOT NULL DEFAULT 0 CHECK (auth_version >= 0),
    banned_at     INTEGER,
    last_login_at INTEGER,
    created_at    INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at    INTEGER NOT NULL CHECK (updated_at >= 0)
) STRICT;

CREATE TABLE IF NOT EXISTS roles (
    key          TEXT    PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 64),
    display_name TEXT    NOT NULL CHECK (length(display_name) BETWEEN 1 AND 64),
    rank         INTEGER NOT NULL CHECK (rank BETWEEN 0 AND 1000000),
    builtin      INTEGER NOT NULL CHECK (builtin IN (0, 1)),
    immutable    INTEGER NOT NULL CHECK (immutable IN (0, 1)),
    created_at   INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at   INTEGER NOT NULL CHECK (updated_at >= 0),
    version      INTEGER NOT NULL CHECK (version >= 1),
    CHECK (
        (key = 'owner' AND rank = 1000000 AND builtin = 1 AND immutable = 1) OR
        (key <> 'owner' AND rank < 1000000 AND immutable = 0)
    )
) STRICT;

CREATE TABLE IF NOT EXISTS channel_groups (
    id         INTEGER PRIMARY KEY CHECK (id > 0),
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    position   INTEGER NOT NULL CHECK (position BETWEEN -2147483648 AND 2147483647),
    visibility TEXT    NOT NULL CHECK (visibility IN ('public', 'private')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    version    INTEGER NOT NULL CHECK (version >= 1)
) STRICT;

CREATE TABLE IF NOT EXISTS channels (
    id         INTEGER PRIMARY KEY CHECK (id > 0),
    group_id   INTEGER REFERENCES channel_groups(id) ON DELETE RESTRICT,
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    mode       TEXT    NOT NULL CHECK (mode IN ('voice', 'text', 'announcement')),
    temporary  INTEGER NOT NULL CHECK (temporary IN (0, 1)),
    visibility TEXT    NOT NULL CHECK (visibility IN ('public', 'private')),
    capacity   INTEGER NOT NULL CHECK (capacity BETWEEN 1 AND 256),
    position   INTEGER NOT NULL CHECK (position BETWEEN -2147483648 AND 2147483647),
    pinned     INTEGER NOT NULL CHECK (pinned IN (0, 1)),
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    version    INTEGER NOT NULL CHECK (version >= 1),
    CHECK (temporary = 0 OR mode = 'voice')
) STRICT;

CREATE TABLE IF NOT EXISTS group_access (
    id             INTEGER PRIMARY KEY CHECK (id > 0),
    group_id       INTEGER NOT NULL REFERENCES channel_groups(id) ON DELETE CASCADE,
    principal_type TEXT    NOT NULL CHECK (principal_type IN ('user', 'role')),
    user_id        INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_key       TEXT    REFERENCES roles(key) ON DELETE RESTRICT,
    created_at     INTEGER NOT NULL CHECK (created_at >= 0),
    CHECK (
        (principal_type = 'user' AND user_id IS NOT NULL AND role_key IS NULL) OR
        (principal_type = 'role' AND user_id IS NULL AND role_key IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS group_access_user_unique
    ON group_access(group_id, user_id) WHERE principal_type = 'user';
CREATE UNIQUE INDEX IF NOT EXISTS group_access_role_unique
    ON group_access(group_id, role_key) WHERE principal_type = 'role';

CREATE TABLE IF NOT EXISTS channel_access (
    id             INTEGER PRIMARY KEY CHECK (id > 0),
    channel_id     INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    principal_type TEXT    NOT NULL CHECK (principal_type IN ('user', 'role')),
    user_id        INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_key       TEXT    REFERENCES roles(key) ON DELETE RESTRICT,
    created_at     INTEGER NOT NULL CHECK (created_at >= 0),
    CHECK (
        (principal_type = 'user' AND user_id IS NOT NULL AND role_key IS NULL) OR
        (principal_type = 'role' AND user_id IS NULL AND role_key IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS channel_access_user_unique
    ON channel_access(channel_id, user_id) WHERE principal_type = 'user';
CREATE UNIQUE INDEX IF NOT EXISTS channel_access_role_unique
    ON channel_access(channel_id, role_key) WHERE principal_type = 'role';

CREATE TABLE IF NOT EXISTS scope_permission_configs (
    scope_type TEXT    NOT NULL CHECK (scope_type IN ('server', 'group', 'channel')),
    group_id   INTEGER REFERENCES channel_groups(id) ON DELETE CASCADE,
    channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE,
    config     TEXT    NOT NULL CHECK (json_valid(config)),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    version    INTEGER NOT NULL CHECK (version >= 1),
    CHECK (
        (scope_type = 'server' AND group_id IS NULL AND channel_id IS NULL) OR
        (scope_type = 'group' AND group_id IS NOT NULL AND channel_id IS NULL) OR
        (scope_type = 'channel' AND group_id IS NULL AND channel_id IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS scope_permission_configs_server_unique
    ON scope_permission_configs(scope_type) WHERE scope_type = 'server';
CREATE UNIQUE INDEX IF NOT EXISTS scope_permission_configs_group_unique
    ON scope_permission_configs(group_id) WHERE scope_type = 'group';
CREATE UNIQUE INDEX IF NOT EXISTS scope_permission_configs_channel_unique
    ON scope_permission_configs(channel_id) WHERE scope_type = 'channel';

CREATE TABLE IF NOT EXISTS user_role_bindings (
    id         INTEGER PRIMARY KEY CHECK (id > 0),
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_key   TEXT    NOT NULL REFERENCES roles(key) ON DELETE RESTRICT,
    scope_type TEXT    NOT NULL CHECK (scope_type IN ('server', 'group', 'channel')),
    group_id   INTEGER REFERENCES channel_groups(id) ON DELETE CASCADE,
    channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    CHECK (
        (scope_type = 'server' AND group_id IS NULL AND channel_id IS NULL) OR
        (scope_type = 'group' AND group_id IS NOT NULL AND channel_id IS NULL) OR
        (scope_type = 'channel' AND group_id IS NULL AND channel_id IS NOT NULL)
    ),
    CHECK (role_key <> 'owner' OR scope_type = 'server')
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS user_role_bindings_server_unique
    ON user_role_bindings(user_id, role_key) WHERE scope_type = 'server';
CREATE UNIQUE INDEX IF NOT EXISTS user_role_bindings_group_unique
    ON user_role_bindings(user_id, role_key, group_id) WHERE scope_type = 'group';
CREATE UNIQUE INDEX IF NOT EXISTS user_role_bindings_channel_unique
    ON user_role_bindings(user_id, role_key, channel_id) WHERE scope_type = 'channel';
CREATE UNIQUE INDEX IF NOT EXISTS user_role_bindings_owner_unique
    ON user_role_bindings(role_key) WHERE role_key = 'owner';

CREATE TABLE IF NOT EXISTS moderation_mutes (
    id         INTEGER PRIMARY KEY CHECK (id > 0),
    scope_type TEXT    NOT NULL CHECK (scope_type IN ('server', 'group', 'channel')),
    group_id   INTEGER REFERENCES channel_groups(id) ON DELETE CASCADE,
    channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('text', 'voice', 'desktop_audio')),
    expires_at INTEGER,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    reason     TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    version    INTEGER NOT NULL CHECK (version >= 1),
    CHECK (
        (scope_type = 'server' AND group_id IS NULL AND channel_id IS NULL) OR
        (scope_type = 'group' AND group_id IS NOT NULL AND channel_id IS NULL) OR
        (scope_type = 'channel' AND group_id IS NULL AND channel_id IS NOT NULL)
    ),
    CHECK (expires_at IS NULL OR expires_at > created_at)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS moderation_mutes_server_unique
    ON moderation_mutes(user_id, kind) WHERE scope_type = 'server';
CREATE UNIQUE INDEX IF NOT EXISTS moderation_mutes_group_unique
    ON moderation_mutes(group_id, user_id, kind) WHERE scope_type = 'group';
CREATE UNIQUE INDEX IF NOT EXISTS moderation_mutes_channel_unique
    ON moderation_mutes(channel_id, user_id, kind) WHERE scope_type = 'channel';

CREATE TABLE IF NOT EXISTS installation_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    installation_id TEXT    NOT NULL UNIQUE CHECK (length(installation_id) = 32 AND installation_id NOT GLOB '*[^0-9a-f]*'),
    initialized     INTEGER NOT NULL DEFAULT 0 CHECK (initialized IN (0, 1))
) STRICT;

CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY CHECK (id > 0),
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       TEXT    NOT NULL,
    token_hash      TEXT    NOT NULL UNIQUE,
    prev_token_hash TEXT,
    expires_at      INTEGER NOT NULL CHECK (expires_at >= 0),
    last_used_at    INTEGER NOT NULL CHECK (last_used_at >= 0),
    created_at      INTEGER NOT NULL CHECK (created_at >= 0),
    UNIQUE (user_id, device_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_prev_token_hash
    ON sessions(prev_token_hash) WHERE prev_token_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS invites (
    id         INTEGER PRIMARY KEY CHECK (id > 0),
    code_hash  TEXT    NOT NULL UNIQUE,
    role_key   TEXT    NOT NULL REFERENCES roles(key) ON DELETE RESTRICT,
    uses_left  INTEGER NOT NULL DEFAULT 1 CHECK (uses_left >= 0),
    expires_at INTEGER,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    CHECK (role_key <> 'owner')
) STRICT;

CREATE TABLE IF NOT EXISTS objects (
    bucket        TEXT NOT NULL,
    name          TEXT NOT NULL,
    content_type  TEXT NOT NULL,
    size          INTEGER NOT NULL CHECK (size >= 0),
    original_name TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (bucket, name)
) STRICT;

CREATE TABLE IF NOT EXISTS command_idempotency (
    principal_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idempotency_key  TEXT    NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 64),
    endpoint         TEXT    NOT NULL CHECK (length(endpoint) BETWEEN 1 AND 256),
    request_hmac     TEXT    NOT NULL CHECK (length(request_hmac) = 64),
    command_id       INTEGER NOT NULL UNIQUE CHECK (command_id > 0),
    status           INTEGER NOT NULL CHECK (status BETWEEN 100 AND 599),
    result_body      TEXT    NOT NULL CHECK (json_valid(result_body)),
    etag             TEXT,
    parent_etag      TEXT,
    location         TEXT,
    cache_control    TEXT,
    pragma           TEXT,
    stream_epoch     TEXT    NOT NULL CHECK (length(stream_epoch) = 32),
    geid             INTEGER NOT NULL CHECK (geid >= 0),
    state_cursor     TEXT    NOT NULL CHECK (length(state_cursor) > 0),
    created_at       INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at       INTEGER NOT NULL CHECK (expires_at > created_at),
    PRIMARY KEY (principal_id, idempotency_key)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_command_idempotency_expires
    ON command_idempotency(expires_at, created_at);

CREATE TABLE IF NOT EXISTS activation_idempotency (
    installation_id      TEXT    NOT NULL REFERENCES installation_state(installation_id) ON DELETE CASCADE,
    idempotency_key      TEXT    NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 64),
    activation_code_hash TEXT    NOT NULL CHECK (length(activation_code_hash) = 64 AND activation_code_hash NOT GLOB '*[^0-9a-f]*'),
    request_hmac         TEXT    NOT NULL CHECK (length(request_hmac) = 64 AND request_hmac NOT GLOB '*[^0-9a-f]*'),
    command_id           INTEGER NOT NULL UNIQUE CHECK (command_id > 0),
    status               INTEGER NOT NULL CHECK (status BETWEEN 100 AND 599),
    result_body          TEXT    NOT NULL CHECK (json_valid(result_body)),
    etag                 TEXT,
    location             TEXT,
    cache_control        TEXT,
    pragma               TEXT,
    created_at           INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at           INTEGER NOT NULL CHECK (expires_at > created_at),
    PRIMARY KEY (installation_id, idempotency_key)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_activation_idempotency_expires
    ON activation_idempotency(expires_at, created_at);
