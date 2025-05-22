package tests

import (
	"github.com/brianvoe/gofakeit/v7"
	"github.com/golang-jwt/jwt/v5"
	ssov1 "github.com/radahn42/protos/gen/proto/sso"
	"github.com/radahn42/sso/tests/suite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
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

	token := respLogin.GetToken()
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

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"], deltaSeconds)
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

func TestLoginWithWrongPassword_ShouldFail(t *testing.T) {
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
		Password: "wrong-password",
		AppId:    appID,
	})

	assert.Error(t, err, "error is expected when logging in with an invalid password")
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

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, false, false, passDefaultLen)
}
