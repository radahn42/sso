-- +goose Up
-- +goose StatementBegin
-- Таблица для ролей
CREATE TABLE IF NOT EXISTS roles
(
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT
);

-- Таблица для разрешений
CREATE TABLE IF NOT EXISTS permissions
(
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT
);

-- Связывающая таблица между ролями и разрешениями (many-to-many)
CREATE TABLE IF NOT EXISTS role_permissions
(
    role_id       INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

-- Связывающая таблица между пользователями и ролями (many-to-many)
CREATE TABLE IF NOT EXISTS user_roles
(
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

-- Таблица Refresh токенов
CREATE TABLE IF NOT EXISTS refresh_tokens
(
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    token      TEXT    NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Таблица отозванных JWT токенов (черный список)
CREATE TABLE IF NOT EXISTS revoked_tokens
(
    token_jti  TEXT PRIMARY KEY NOT NULL, -- jti (JWT ID) токена
    expires_at INTEGER          NOT NULL
);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS revoked_tokens;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
-- +goose StatementEnd