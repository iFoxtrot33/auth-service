package auth

import (
	"AuthService/config"
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
		return nil, errors.New("github provider not implemented")
	default:
		f.logger.Error().Str("provider", name).Msg("Unknown provider")
		return nil, errors.New("unknown provider")
	}
}

func generateRandomState() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
