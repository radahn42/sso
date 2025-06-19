package authctx

import "context"

type ctxKey string

const (
	userIDKey ctxKey = "user_id"
	appIDKey  ctxKey = "app_id"
)

// SetUserID returns a new context with the given user ID set.
func SetUserID(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// SetAppID returns a new context with the given app ID set.
func SetAppID(ctx context.Context, appID int) context.Context {
	return context.WithValue(ctx, appIDKey, appID)
}

// UserID retrieves the user ID from the context.
// Returns the ID and true if present and of correct type, otherwise returns zero and false.
func UserID(ctx context.Context) (int64, bool) {
	userID, ok := ctx.Value(userIDKey).(int64)
	return userID, ok
}

// AppID retrieves the app ID from the context.
// Returns the ID and true if present and of correct type, otherwise returns zero and false.
func AppID(ctx context.Context) (int, bool) {
	appID, ok := ctx.Value(appIDKey).(int)
	return appID, ok
}
