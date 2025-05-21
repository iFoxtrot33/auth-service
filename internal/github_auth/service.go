package github_auth

import (
	"AuthService/config"
	"AuthService/pkg/types"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

type GitHubProvider struct {
	oauthConfig *oauth2.Config
	logger      *zerolog.Logger
}

func NewGitHubProvider(cfg *config.Config, logger *zerolog.Logger) *GitHubProvider {
	oauthConfig := cfg.Auth.GitHub.GetOAuthConfig()
	return &GitHubProvider{
		oauthConfig: oauthConfig,
		logger:      logger,
	}
}

func (g *GitHubProvider) GetAuthURL(state string) string {
	if state == "" {
		g.logger.Error().Msg("Empty state provided for GitHub OAuth URL")
		return ""
	}
	g.logger.Info().Msg("Generating GitHub OAuth URL")
	// Изменение: Используем scope=user для получения email и refresh_token
	url := g.oauthConfig.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("scope", "user refresh_token"),
		oauth2.SetAuthURLParam("prompt", "consent"),
	)
	g.logger.Info().Str("auth_url", url).Msg("Generated GitHub OAuth URL")
	return url
}

func (g *GitHubProvider) Authenticate(code string) (types.UserInfo, *oauth2.Token, error) {
	if code == "" {
		g.logger.Error().Msg("Empty code provided for GitHub authentication")
		return types.UserInfo{}, nil, errors.New("empty code")
	}

	token, err := g.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		g.logger.Error().Err(err).Msg("Failed to exchange code with GitHub")
		return types.UserInfo{}, nil, err
	}

	g.logger.Info().
		Str("access_token", token.AccessToken[:10]+"...").
		Str("refresh_token", token.RefreshToken).
		Str("token_type", token.TokenType).
		Interface("expiry", token.Expiry).
		Msg("GitHub OAuth token received")

	client := g.oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		g.logger.Error().Err(err).Msg("Failed to get user info from GitHub")
		return types.UserInfo{}, nil, err
	}
	defer resp.Body.Close()

	var userInfo struct {
		ID    int    `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		g.logger.Error().Err(err).Msg("Failed to decode GitHub user info")
		return types.UserInfo{}, nil, err
	}

	// Пытаемся получить email через emails endpoint
	if userInfo.Email == "" {
		resp, err := client.Get("https://api.github.com/user/emails")
		if err != nil {
			g.logger.Warn().Err(err).Msg("Failed to get email info from GitHub")
		} else {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				g.logger.Warn().Err(err).Msg("Failed to read GitHub emails response")
			} else if resp.StatusCode != http.StatusOK {
				g.logger.Warn().
					Int("status_code", resp.StatusCode).
					Str("body", string(body)).
					Msg("GitHub emails endpoint failed")
			} else {
				var emails []struct {
					Email    string `json:"email"`
					Primary  bool   `json:"primary"`
					Verified bool   `json:"verified"`
				}
				if err := json.Unmarshal(body, &emails); err != nil {
					g.logger.Warn().Err(err).Msg("Failed to decode GitHub email info")
				} else {
					for _, email := range emails {
						if email.Primary && email.Verified {
							userInfo.Email = email.Email
							break
						}
					}
				}
			}
		}
	}

	// Используем Login как Email, если email пустой
	if userInfo.Email == "" {
		userInfo.Email = userInfo.Login
		g.logger.Info().
			Str("login", userInfo.Login).
			Msg("Using GitHub login as identifier due to empty email")
	}

	g.logger.Info().
		Str("identifier", userInfo.Email).
		Str("login", userInfo.Login).
		Msg("Successfully retrieved GitHub user info")

	return types.UserInfo{
		ID:    fmt.Sprintf("%d", userInfo.ID),
		Email: userInfo.Email, // Email или Login
		Name:  userInfo.Name,
	}, token, nil
}

func (g *GitHubProvider) ValidateRefreshToken(refreshToken, expectedIdentifier string) error {
	if refreshToken == "" {
		g.logger.Error().Msg("Empty refresh token provided for validation")
		return errors.New("empty refresh token")
	}
	if expectedIdentifier == "" {
		g.logger.Error().Msg("Empty expected identifier provided for validation")
		return errors.New("empty expected identifier")
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
		return errors.New("invalid or expired refresh token")
	}

	// Проверяем информацию о пользователе с новым access_token
	client := oauth2.NewClient(context.Background(), tokenSource)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		g.logger.Error().
			Err(err).
			Str("access_token", newToken.AccessToken[:10]+"...").
			Msg("Failed to get user info with new access token")
		return errors.New("failed to validate user info")
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		g.logger.Error().Err(err).Msg("Failed to decode GitHub user info")
		return errors.New("failed to decode user info")
	}

	// Пытаемся получить email через emails endpoint
	if userInfo.Email == "" {
		resp, err := client.Get("https://api.github.com/user/emails")
		if err != nil {
			g.logger.Warn().Err(err).Msg("Failed to get email info from GitHub")
		} else {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				g.logger.Warn().Err(err).Msg("Failed to read GitHub emails response")
			} else if resp.StatusCode != http.StatusOK {
				g.logger.Warn().
					Int("status_code", resp.StatusCode).
					Str("body", string(body)).
					Msg("GitHub emails endpoint failed")
			} else {
				var emails []struct {
					Email    string `json:"email"`
					Primary  bool   `json:"primary"`
					Verified bool   `json:"verified"`
				}
				if err := json.Unmarshal(body, &emails); err != nil {
					g.logger.Warn().Err(err).Msg("Failed to decode GitHub email info")
				} else {
					for _, email := range emails {
						if email.Primary && email.Verified {
							userInfo.Email = email.Email
							break
						}
					}
				}
			}
		}
	}

	// Используем Email, если доступен, иначе Login
	identifier := userInfo.Email
	if identifier == "" {
		identifier = userInfo.Login
	}

	if identifier == "" {
		g.logger.Error().Msg("No identifier (email or login) returned in user info")
		return errors.New("invalid user info")
	}

	if identifier != expectedIdentifier {
		g.logger.Error().
			Str("expected_identifier", expectedIdentifier).
			Str("received_identifier", identifier).
			Msg("Identifier mismatch in user info")
		return errors.New("identifier mismatch")
	}

	g.logger.Info().
		Str("identifier", identifier).
		Str("access_token", newToken.AccessToken[:10]+"...").
		Msg("Refresh token validated successfully")
	return nil
}
