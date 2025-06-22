package tests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/golang-jwt/jwt/v5"
	ssov1 "github.com/radahn42/protos/gen/sso/v1"
	"github.com/radahn42/sso/tests/suite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	emptyAppID = 0
	appID      = 1
	appSecret  = "test-secret"

	passDefaultLen = 10
)

func TestRegisterLogin_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	loginTime := time.Now()

	token := respLogin.GetAccessToken()
	assert.NotEmpty(t, token)

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	uidFloat, ok := claims["uid"].(float64)
	require.True(t, ok, "uid claim is not a float64")

	uid := int64(uidFloat)
	assert.Equal(t, respReg.GetUserId(), uid)

	assert.Equal(t, email, claims["email"])

	appIDFloat, ok := claims["app_id"].(float64)
	require.True(t, ok, "app_id claim is not a float64")
	appIDFromClaims := int(appIDFloat)
	assert.Equal(t, appID, appIDFromClaims)

	const deltaSeconds = 1

	assert.InDelta(t, loginTime.Add(st.Cfg.AccessTokenTTL).Unix(), claims["exp"], deltaSeconds)
}

func TestLoginWithNonExistentApp_ShouldFail(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    emptyAppID,
	})

	assert.Error(t, err, "error is expected when logging in with a non-existent app_id")
}

func TestRegisterExistingUser_ShouldFail(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	_, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})

	assert.Error(t, err, "error is expected when re-registering with the same email address")
}

func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		expectedErr string
	}{
		{
			name:        "Register with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			expectedErr: "rpc error: code = InvalidArgument desc = validation error:\n - password: value length must be at least 8 characters [string.min_len]",
		},
		{
			name:        "Register with Empty Email",
			email:       "",
			password:    randomFakePassword(),
			expectedErr: "rpc error: code = InvalidArgument desc = validation error:\n - email: value is empty, which is not a valid email address [string.email_empty]",
		},
		{
			name:        "Register with Both Empty",
			email:       "",
			password:    "",
			expectedErr: "rpc error: code = InvalidArgument desc = validation error:\n - email: value is empty, which is not a valid email address [string.email_empty]\n - password: value length must be at least 8 characters [string.min_len]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.email,
				Password: tt.password,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		appID       int32
		expectedErr string
	}{
		{
			name:        "Login with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			appID:       appID,
			expectedErr: "rpc error: code = InvalidArgument desc = validation error:\n - password: value length must be at least 8 characters [string.min_len]",
		},
		{
			name:        "Login with Empty Email",
			email:       "",
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "rpc error: code = InvalidArgument desc = validation error:\n - email: value is empty, which is not a valid email address [string.email_empty]",
		},
		{
			name:        "Login with Wrong Password",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "rpc error: code = InvalidArgument desc = invalid credentials",
		},
		{
			name:        "Login with Both Empty",
			email:       "",
			password:    "",
			appID:       appID,
			expectedErr: "rpc error: code = InvalidArgument desc = validation error:\n - email: value is empty, which is not a valid email address [string.email_empty]\n - password: value length must be at least 8 characters [string.min_len]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
				Email:    tt.email,
				Password: tt.password,
				AppId:    tt.appID,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, false, false, passDefaultLen)
}
