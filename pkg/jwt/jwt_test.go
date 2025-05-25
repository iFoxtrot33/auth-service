package jwt

import (
	"AuthService/config"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestConfig() *config.Config {
	return &config.Config{
		Auth: config.AuthConfig{
			JWT: config.JWTConfig{
				Secret:           "test-secret-key",
				AccessExpiresIn:  3600,
				RefreshExpiresIn: 86400,
			},
		},
	}
}

func createTestJWTData() JWTData {
	return JWTData{
		Email:    "test@example.com",
		Name:     "Test User",
		Provider: "google",
	}
}

func TestCreateAndParseToken(t *testing.T) {
	cfg := createTestConfig()
	jwtService := NewJWT(cfg)
	data := createTestJWTData()

	token, err := jwtService.CreateAccessToken(data)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	parsedData, err := jwtService.Parse(token)
	require.NoError(t, err)

	assert.Equal(t, data.Email, parsedData.Email)
	assert.Equal(t, data.Name, parsedData.Name)
	assert.Equal(t, data.Provider, parsedData.Provider)
}

func TestParseInvalidToken(t *testing.T) {
	cfg := createTestConfig()
	jwtService := NewJWT(cfg)

	_, err := jwtService.Parse("invalid.token")
	assert.Error(t, err)
}

func TestExpiredToken(t *testing.T) {
	cfg := createTestConfig()
	cfg.Auth.JWT.AccessExpiresIn = -1
	jwtService := NewJWT(cfg)
	data := createTestJWTData()

	token, err := jwtService.CreateAccessToken(data)
	require.NoError(t, err)

	time.Sleep(time.Millisecond * 10)

	_, err = jwtService.Parse(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}
