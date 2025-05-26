package storage

import "errors"

var (
	ErrUserExists          = errors.New("user already exists")
	ErrUserNotFound        = errors.New("user not found")
	ErrAppNotFound         = errors.New("app not found")
	ErrNotFound            = errors.New("entity not found")      // Универсальная ошибка для отсутствия записи
	ErrAlreadyExists       = errors.New("entity already exists") // Универсальная ошибка для дублирования
	ErrConflict            = errors.New("conflict in storage")   // Для других типов конфликтов
	ErrInvalidID           = errors.New("invalid ID format")
	ErrForeignKeyViolation = errors.New("foreign key constraint violation")
	ErrInternal            = errors.New("internal storage error")
	ErrNotImplemented      = errors.New("operation not implemented by this storage")
)
