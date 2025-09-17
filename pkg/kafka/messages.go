package kafka

import "time"

const (
	MessageTypeUserAuthenticated = "USER_AUTHENTICATED"
	MessageTypeUserLogout        = "USER_LOGOUT"
)

type UserAuthenticatedMessage struct {
	Type           string          `json:"type"`
	UserID         string          `json:"user_id"`
	Provider       string          `json:"provider"`
	SessionID      string          `json:"session_id"`
	ProviderTokens *ProviderTokens `json:"provider_tokens,omitempty"`
	Timestamp      time.Time       `json:"timestamp"`
}

type UserLogoutMessage struct {
	Type      string    `json:"type"`
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`
}

type ProviderTokens struct {
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}
