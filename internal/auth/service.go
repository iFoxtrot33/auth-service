package auth

import (
	"AuthService/config"
	"AuthService/internal/github_auth"
	"AuthService/internal/google_auth"
	"AuthService/pkg/types"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

type Provider interface {
	GetAuthURL(state string) string
	Authenticate(code string) (types.UserInfo, *oauth2.Token, error)
	ValidateRefreshToken(refreshToken string, email string) error
}

type ProviderFactory interface {
	GetProvider(name string) (Provider, error)
}

type providerFactory struct {
	config *config.Config
	logger *zerolog.Logger
}

func NewProviderFactory(config *config.Config, logger *zerolog.Logger) ProviderFactory {
	return &providerFactory{
		config: config,
		logger: logger,
	}
}

func (f *providerFactory) GetProvider(name string) (Provider, error) {
	switch name {
	case "google":
		return google_auth.NewGoogleProvider(f.config, f.logger), nil
	case "telegram":
		return nil, errors.New("telegram provider not implemented")
	case "github":
		return github_auth.NewGitHubProvider(f.config, f.logger), nil
	default:
		f.logger.Error().Str("provider", name).Msg("Unknown provider")
		return nil, errors.New("unknown provider")
	}
}

func ValidateUserWithRefreshToken(factory ProviderFactory, logger Logger, providerName, identifier, refreshToken string) error {
	if providerName == "" || identifier == "" || refreshToken == "" {
		logger.Error().
			Str("provider", providerName).
			Str("identifier", identifier).
			Msg("Provider, identifier, or refresh token is empty")
		return errors.New("provider, identifier, or refresh token is empty")
	}

	provider, err := factory.GetProvider(providerName)
	if err != nil {
		logger.Error().
			Err(err).
			Str("provider", providerName).
			Msg("Failed to get provider")
		return err
	}

	err = provider.ValidateRefreshToken(refreshToken, identifier)
	if err != nil {
		logger.Error().
			Err(err).
			Str("provider", providerName).
			Str("identifier", identifier).
			Str("refresh_token", refreshToken[:10]+"...").
			Msg("Failed to validate refresh token")
		return err
	}

	logger.Info().
		Str("provider", providerName).
		Str("identifier", identifier).
		Msg("Refresh token validated successfully")
	return nil
}

func generateRandomState() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
