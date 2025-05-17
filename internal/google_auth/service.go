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
	g.logger.Info().Msg("Generating Google OAuth URL")
	return g.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
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
