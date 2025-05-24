package google_auth

import (
	"AuthService/config"
	"AuthService/pkg/types"
	"context"
	"encoding/json"
	"errors"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

type GoogleProvider struct {
	oauthConfig *oauth2.Config
	logger      *zerolog.Logger
}

func NewGoogleProvider(cfg *config.Config, logger *zerolog.Logger) *GoogleProvider {
	return &GoogleProvider{
		oauthConfig: cfg.Auth.Google.GetOAuthConfig(),
		logger:      logger,
	}
}

func (g *GoogleProvider) GetAuthURL(state string) string {
	if state == "" {
		g.logger.Error().Msg("Empty state provided for Google OAuth URL")
		return ""
	}
	url := g.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
	g.logger.Info().Msg("Generating Google OAuth URL")
	return url
}

func (g *GoogleProvider) Authenticate(code string) (types.UserInfo, *oauth2.Token, error) {
	if code == "" {
		g.logger.Error().Msg("Empty code provided for Google authentication")
		return types.UserInfo{}, nil, errors.New("empty code")
	}

	token, err := g.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		g.logger.Error().Err(err).Msg("Failed to exchange code with Google")
		return types.UserInfo{}, nil, err
	}

	g.logger.Info().
		Str("access_token", token.AccessToken[:10]+"...").
		Str("refresh_token", token.RefreshToken).
		Str("token_type", token.TokenType).
		Interface("expiry", token.Expiry).
		Msg("Google OAuth token received")

	client := g.oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		g.logger.Error().Err(err).Msg("Failed to get user info from Google")
		return types.UserInfo{}, nil, err
	}
	defer resp.Body.Close()

	var userInfo struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		g.logger.Error().Err(err).Msg("Failed to decode Google user info")
		return types.UserInfo{}, nil, err
	}

	g.logger.Info().Str("email", userInfo.Email).Msg("Successfully retrieved Google user info")

	return types.UserInfo{
		ID:    userInfo.ID,
		Email: userInfo.Email,
		Name:  userInfo.Name,
	}, token, nil
}

func (g *GoogleProvider) ValidateRefreshToken(refreshToken, expectedEmail string) (string, error) {
	if refreshToken == "" {
		g.logger.Error().Msg("Empty refresh token provided for validation")
		return "", errors.New("empty refresh token")
	}
	if expectedEmail == "" {
		g.logger.Error().Msg("Empty expected email provided for validation")
		return "", errors.New("empty expected email")
	}

	// Создаём токен с refresh_token
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	// Используем TokenSource для попытки обновления access_token
	tokenSource := g.oauthConfig.TokenSource(context.Background(), token)
	newToken, err := tokenSource.Token()
	if err != nil {
		g.logger.Error().
			Err(err).
			Str("refresh_token", refreshToken[:10]+"...").
			Msg("Failed to validate refresh token via TokenSource")
		return "", errors.New("invalid or expired refresh token")
	}

	// Проверяем информацию о пользователе с новым access_token
	client := oauth2.NewClient(context.Background(), tokenSource)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		g.logger.Error().
			Err(err).
			Str("access_token", newToken.AccessToken[:10]+"...").
			Msg("Failed to get user info with new access token")
		return "", errors.New("failed to validate user info")
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		g.logger.Error().Err(err).Msg("Failed to decode Google user info")
		return "", errors.New("failed to decode user info")
	}

	if userInfo.Email == "" {
		g.logger.Error().Msg("No email returned in user info")
		return "", errors.New("invalid user info")
	}

	if userInfo.Email != expectedEmail {
		g.logger.Error().
			Str("expected_email", expectedEmail).
			Str("received_email", userInfo.Email).
			Msg("Email mismatch in user info")
		return "", errors.New("email mismatch")
	}

	g.logger.Info().
		Str("email", userInfo.Email).
		Str("access_token", newToken.AccessToken[:10]+"...").
		Msg("Refresh token validated successfully")

	newRefreshToken := newToken.RefreshToken
	if newRefreshToken != "" {
		g.logger.Info().
			Str("new_refresh_token", newRefreshToken[:10]+"...").
			Msg("Received new refresh token from Google")
	}
	return newRefreshToken, nil
}
