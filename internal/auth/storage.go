package auth

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

type Token struct {
	OAuthToken string
}

type TokenStorage struct {
	tokens      map[string]Token
	tokenToUser map[string]string
	mu          sync.RWMutex
}

func NewTokenStorage() *TokenStorage {
	return &TokenStorage{
		tokens:      make(map[string]Token),
		tokenToUser: make(map[string]string),
	}
}

func (s *TokenStorage) SaveToken(email, provider, token string) error {
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

	existingToken.OAuthToken = token
	s.tokens[key] = existingToken
	s.tokenToUser[token] = key

	fmt.Printf("Saved token: key=%s, token=%s\n", key, token[:10]+"...")
	return nil
}

func (s *TokenStorage) GetToken(email, provider string) (string, error) {
	if email == "" || provider == "" {
		return "", errors.New("email or provider is empty")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := fmt.Sprintf("%s:%s", email, provider)

	token, exists := s.tokens[key]
	if !exists {
		return "", errors.New("token not found")
	}

	if token.OAuthToken == "" {
		return "", errors.New("OAuth token not found")
	}
	return token.OAuthToken, nil
}

func (s *TokenStorage) FindByToken(token string) (identifier, provider string, err error) {
	if token == "" {
		return "", "", errors.New("token is empty")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.tokenToUser[token]
	if !exists {
		return "", "", errors.New("token not found")
	}

	parts := strings.Split(key, ":")
	if len(parts) != 2 {
		return "", "", errors.New("invalid token key format")
	}

	tokenData, exists := s.tokens[key]
	if !exists || tokenData.OAuthToken != token {
		return "", "", errors.New("token data not found or mismatched")
	}

	return parts[0], parts[1], nil
}
