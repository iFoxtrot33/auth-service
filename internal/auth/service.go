package auth

import (
	"AuthService/config"
	"AuthService/internal/github_auth"
	"AuthService/internal/google_auth"
	"AuthService/internal/telegram_auth"
	"AuthService/pkg/types"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

type Provider interface {
	GetAuthURL(state string) string
	Authenticate(code string) (types.UserInfo, *oauth2.Token, error)
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
	if !isProviderEnabled(name, f.config.Auth.EnabledProviders) {
		f.logger.Error().Str("provider", name).Msg("Provider is disabled in configuration")
		return nil, errors.New("provider is disabled")
	}

	switch name {
	case "google":
		return google_auth.NewGoogleProvider(f.config, f.logger), nil
	case "telegram_bot":
		return telegram_auth.NewTelegramProvider(f.config, f.logger, true), nil
	case "telegram_widget":
		return telegram_auth.NewTelegramProvider(f.config, f.logger, false), nil
	case "github":
		return github_auth.NewGitHubProvider(f.config, f.logger), nil
	default:
		f.logger.Error().Str("provider", name).Msg("Unknown provider")
		return nil, errors.New("unknown provider")
	}
}

func isProviderEnabled(provider string, enabledProviders []string) bool {
	if len(enabledProviders) == 0 {
		return true
	}
	for _, p := range enabledProviders {
		if strings.EqualFold(p, provider) {
			return true
		}
	}
	return false
}

func generateRandomState() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
