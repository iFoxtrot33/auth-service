// auth/storage.go
package auth

import (
	"errors"
	"fmt"
	"sync"
)

type Token struct {
	OAuthToken  string
	CustomToken string
}

type TokenStorage struct {
	tokens map[string]Token
	mu     sync.RWMutex
}

func NewTokenStorage() *TokenStorage {
	return &TokenStorage{
		tokens: make(map[string]Token),
	}
}

func (s *TokenStorage) SaveToken(email, provider, tokenType, token string) error {
	if email == "" || provider == "" || token == "" {
		return errors.New("email, provider, or token is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%s:%s", email, provider)

	existingToken, exists := s.tokens[key]
	if !exists {
		existingToken = Token{}
	}

	switch tokenType {
	case "oauth":
		existingToken.OAuthToken = token
	case "jwt":
		existingToken.CustomToken = token
	default:
		return errors.New("invalid token type")
	}

	s.tokens[key] = existingToken
	fmt.Printf("Saved token: key=%s, type=%s, token=%s\n", key, tokenType, token[:10]+"...")
	return nil
}

func (s *TokenStorage) GetToken(email, provider, tokenType string) (string, error) {
	if email == "" || provider == "" || tokenType == "" {
		return "", errors.New("email, provider, or token type is empty")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := fmt.Sprintf("%s:%s", email, provider)

	token, exists := s.tokens[key]
	if !exists {
		return "", errors.New("token not found")
	}

	switch tokenType {
	case "oauth":
		if token.OAuthToken == "" {
			return "", errors.New("OAuth token not found")
		}
		return token.OAuthToken, nil
	case "jwt":
		if token.CustomToken == "" {
			return "", errors.New("JWT token not found")
		}
		return token.CustomToken, nil
	default:
		return "", errors.New("invalid token type")
	}
}
