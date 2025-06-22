-- +goose Up
-- +goose StatementBegin
-- Seed roles
INSERT INTO roles (id, name, description) VALUES
  (1, 'admin', 'Administrator with full access'),
  (2, 'user', 'Regular authenticated user');

-- Seed permissions
INSERT INTO permissions (id, name, description) VALUES
  (1, 'roles:create', 'Permission to create a role'),
  (2, 'roles:read', 'Permission to read roles'),
  (3, 'roles:update', 'Permission to update roles'),
  (4, 'roles:delete', 'Permission to delete roles'),

  (5, 'permissions:create', 'Create new permission'),
  (6, 'permissions:read', 'Read existing permissions'),
  (7, 'permissions:update', 'Update existing permissions'),
  (8, 'permissions:delete', 'Delete existing permissions'),

  (9, 'users:read', 'Read user data'),

  (10, 'auth:reset_password', 'Request/Confirm password reset'),
  (11, 'auth:change_password', 'Change password'),
  (12, 'auth:logout', 'Logout'),

  (13, 'tokens:validate', 'Validate access token'),
  (14, 'tokens:refresh', 'Refresh tokens');

-- Assign all permissions to admin
INSERT INTO role_permissions (role_id, permission_id)
SELECT 1, id FROM permissions;

-- Assign limited permissions to user
INSERT INTO role_permissions (role_id, permission_id) VALUES
  (2, 10),  -- auth:reset_password
  (2, 11),  -- auth:change_password
  (2, 12),  -- auth:logout
  (2, 13),  -- tokens:validate
  (2, 14);  -- tokens:refresh

-- Create initial admin user
INSERT INTO users (id, email, pass_hash)
VALUES (1, 'admin@example.com', '$2a$10$zs2Mnb0CsB6FTskiMFuNUe49HI6uFoCEx1OJ8tjfoPm4SX/M05KxK'); -- recommended to generate it with hasher (cmd/hasher)

-- Assign admin role to initial user
INSERT INTO user_roles (user_id, role_id) VALUES (1, 1);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DELETE FROM user_roles WHERE user_id = 1 AND role_id = 1;
DELETE FROM users WHERE id = 1;

DELETE FROM role_permissions WHERE role_id IN (1, 2);
DELETE FROM permissions WHERE id BETWEEN 1 AND 14;
DELETE FROM roles WHERE id IN (1, 2);
-- +goose StatementEnd