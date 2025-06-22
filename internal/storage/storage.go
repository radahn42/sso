package storage

import "errors"

var (
	ErrUserExists          = errors.New("user already exists")
	ErrUserNotFound        = errors.New("user not found")
	ErrAppNotFound         = errors.New("app not found")
	ErrResetTokenNotFound  = errors.New("reset token not found")
	ErrResetTokenExpired   = errors.New("reset token expired")
	ErrNotFound            = errors.New("entity not found")
	ErrAlreadyExists       = errors.New("entity already exists")
	ErrConflict            = errors.New("conflict in storage")
	ErrForeignKeyViolation = errors.New("foreign key constraint violation")
	ErrInternal            = errors.New("internal storage error")
	ErrNotImplemented      = errors.New("operation not implemented by this storage")
)
