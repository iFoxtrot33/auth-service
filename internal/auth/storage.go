// auth/storage.go
package auth

import (
	"errors"
	"fmt"
	"sync"
)

type TokenStorage struct {
	tokens map[string]string
	mu     sync.RWMutex
}

func NewTokenStorage() *TokenStorage {
	return &TokenStorage{
		tokens: make(map[string]string),
	}
}

func (s *TokenStorage) SaveToken(email, provider, refreshToken string) error {
	if email == "" || provider == "" || refreshToken == "" {
		return errors.New("email, provider, or refresh token is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%s:%s", email, provider)
	s.tokens[key] = refreshToken
	return nil
}

// GetToken получает refresh token по email и provider
func (s *TokenStorage) GetToken(email, provider string) (string, error) {
	if email == "" || provider == "" {
		return "", errors.New("email or provider is empty")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := fmt.Sprintf("%s:%s", email, provider)
	token, exists := s.tokens[key]
	if !exists {
		return "", errors.New("refresh token not found")
	}
	return token, nil
}
