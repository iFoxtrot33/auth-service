package auth

import (
	"AuthService/pkg/req"
	"AuthService/pkg/res"
	"net/http"

	"github.com/rs/zerolog"
)

type Logger interface {
	Error() *zerolog.Event
	Info() *zerolog.Event
	Warn() *zerolog.Event
}

type Config interface {
	GetEnvironment() string
}

type AuthHandler struct {
	Logger          Logger
	Config          Config
	ProviderFactory ProviderFactory
	TokenStorage    *TokenStorage
}

type AuthHandlerDeps struct {
	Config          Config
	Logger          Logger
	ProviderFactory ProviderFactory
	TokenStorage    *TokenStorage
}

// NewAuthHandler creates a new auth handler and registers routes
// @Summary Create authentication handler
// @Description Initializes the authentication handler and registers all API routes
func NewAuthHandler(router *http.ServeMux, deps *AuthHandlerDeps) {
	handler := &AuthHandler{
		Logger:          deps.Logger,
		Config:          deps.Config,
		ProviderFactory: deps.ProviderFactory,
		TokenStorage:    deps.TokenStorage,
	}

	router.HandleFunc("GET /api/v1/login", handler.handleLogin())
	router.HandleFunc("GET /api/v1/access", handler.handleAccess())
	router.HandleFunc("POST /api/v1/refresh", handler.handleRefresh())
}

// handleLogin initiates OAuth login by redirecting to the provider's auth URL
// @Summary Initiate OAuth login
// @Description Redirects the user to the OAuth provider's authentication URL. Supported providers: google, github, telegram_bot, telegram_widget
// @Tags auth
// @Accept json
// @Produce json
// @Param provider query string true "OAuth provider" Enums(google, github, telegram_bot, telegram_widget) example(google)
// @Success 307 {string} string "Redirect to provider's auth URL"
// @Failure 400 {object} ErrorResponse "Provider not specified or invalid provider"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/login [get]
func (h *AuthHandler) handleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providerName := r.URL.Query().Get("provider")
		if providerName == "" {
			h.Logger.Error().Msg("Provider not specified")
			res.Json(w, map[string]string{"error": "Provider not specified"}, http.StatusBadRequest)
			return
		}

		provider, err := h.ProviderFactory.GetProvider(providerName)
		if err != nil {
			h.Logger.Error().Err(err).Str("provider", providerName).Msg("Failed to get provider")
			res.Json(w, map[string]string{"error": "Invalid provider"}, http.StatusBadRequest)
			return
		}

		state, err := generateRandomState()
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to generate state")
			res.Json(w, map[string]string{"error": "Internal server error"}, http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    state,
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
			Secure:   h.Config.GetEnvironment() == "production",
			SameSite: http.SameSiteLaxMode,
		})

		url := provider.GetAuthURL(state)
		if url == "" {
			h.Logger.Error().Str("provider", providerName).Msg("Failed to generate auth URL")
			res.Json(w, map[string]string{"error": "Failed to generate auth URL"}, http.StatusInternalServerError)
			return
		}

		h.Logger.Info().Str("provider", providerName).Msg("Redirecting to provider auth URL")
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

// handleAccess completes OAuth authentication and returns provider tokens
// @Summary Complete OAuth authentication
// @Description Exchanges the OAuth code for user info and returns provider access and refresh tokens with provider name
// @Tags auth
// @Accept json
// @Produce json
// @Param provider query string true "OAuth provider" Enums(google, github, telegram_bot, telegram_widget) example(google)
// @Param state query string true "OAuth state parameter for CSRF protection"
// @Param code query string true "OAuth authorization code from provider"
// @Success 200 {object} AccessResponse "Provider access and refresh tokens with provider name"
// @Failure 400 {object} ErrorResponse "Provider not specified, invalid state, code not specified, or user identifier is empty"
// @Failure 500 {object} ErrorResponse "Authentication failed or failed to save tokens"
// @Router /api/v1/access [get]
func (h *AuthHandler) handleAccess() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providerName := r.URL.Query().Get("provider")
		if providerName == "" {
			h.Logger.Error().Msg("Provider not specified")
			res.Json(w, map[string]string{"error": "Provider not specified"}, http.StatusBadRequest)
			return
		}

		provider, err := h.ProviderFactory.GetProvider(providerName)
		if err != nil {
			h.Logger.Error().Err(err).Str("provider", providerName).Msg("Failed to get provider")
			res.Json(w, map[string]string{"error": "Invalid provider"}, http.StatusBadRequest)
			return
		}

		state := r.URL.Query().Get("state")
		cookie, err := r.Cookie("oauth_state")
		if err != nil || cookie.Value != state {
			h.Logger.Error().Msg("Invalid or missing state")
			res.Json(w, map[string]string{"error": "Invalid state"}, http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			h.Logger.Error().Msg("Code not specified")
			res.Json(w, map[string]string{"error": "Code not specified"}, http.StatusBadRequest)
			return
		}

		userInfo, oauthToken, err := provider.Authenticate(code)
		if err != nil {
			h.Logger.Error().Err(err).Str("provider", providerName).Msg("Failed to authenticate")
			res.Json(w, map[string]string{"error": "Authentication failed"}, http.StatusInternalServerError)
			return
		}

		identifier := userInfo.Email
		if identifier == "" {
			h.Logger.Warn().
				Str("provider", providerName).
				Msg("User info identifier is empty")
			res.Json(w, map[string]string{"error": "User identifier is empty"}, http.StatusBadRequest)
			return
		}

		if (providerName == "google" || providerName == "github") && oauthToken.RefreshToken != "" {
			err = h.TokenStorage.SaveToken(identifier, providerName, oauthToken.RefreshToken)
			if err != nil {
				h.Logger.Error().
					Err(err).
					Str("identifier", identifier).
					Str("provider", providerName).
					Str("refresh_token", oauthToken.RefreshToken[:10]+"...").
					Msg("Failed to save OAuth refresh token")
				res.Json(w, map[string]string{"error": "Failed to save token"}, http.StatusInternalServerError)
				return
			}
			h.Logger.Info().Str("identifier", identifier).Str("provider", providerName).Msg("Saved OAuth refresh token")
		}

		response := AccessResponse{
			AccessToken:  oauthToken.AccessToken,
			RefreshToken: oauthToken.RefreshToken, // Empty for Telegram
			Provider:     providerName,
		}
		res.Json(w, response, http.StatusOK)

		h.Logger.Info().Str("identifier", identifier).Str("provider", providerName).Msg("Successfully issued provider tokens")
	}
}

// handleRefresh refreshes provider access token
// @Summary Refresh provider access token
// @Description Refreshes the access token using a refresh token for Google/GitHub providers
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RefreshRequest true "Refresh token request with provider"
// @Success 200 {object} AccessResponse "New provider access and refresh tokens with provider name"
// @Failure 400 {object} ErrorResponse "Invalid request body, invalid or expired refresh token, or refresh not supported"
// @Failure 500 {object} ErrorResponse "Failed to refresh tokens or save tokens"
// @Router /api/v1/refresh [post]
func (h *AuthHandler) handleRefresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refreshReq, err := req.HandleBody[RefreshRequest](&w, r)
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to parse or validate refresh request")
			res.Json(w, map[string]string{"error": "Invalid request body"}, http.StatusBadRequest)
			return
		}

		providerName := refreshReq.Provider

		provider, err := h.ProviderFactory.GetProvider(providerName)
		if err != nil {
			h.Logger.Error().Err(err).Str("provider", providerName).Msg("Failed to get provider")
			res.Json(w, map[string]string{"error": "Invalid provider"}, http.StatusBadRequest)
			return
		}

		if providerName == "telegram_bot" || providerName == "telegram_widget" {
			h.Logger.Error().Str("provider", providerName).Msg("Refresh not supported for Telegram")
			res.Json(w, map[string]string{"error": "Refresh not supported for Telegram"}, http.StatusBadRequest)
			return
		}

		if h.TokenStorage == nil {
			h.Logger.Error().Msg("TokenStorage is nil")
			res.Json(w, map[string]string{"error": "Internal server error"}, http.StatusInternalServerError)
			return
		}

		identifier, storedProvider, err := h.TokenStorage.FindByToken(refreshReq.RefreshToken)
		if err != nil || storedProvider != providerName || identifier == "" {
			h.Logger.Error().
				Err(err).
				Str("provider", providerName).
				Str("stored_provider", storedProvider).
				Str("provided_token", refreshReq.RefreshToken[:10]+"...").
				Msg("Refresh token not found, mismatched provider, or invalid identifier")
			res.Json(w, map[string]string{"error": "Invalid refresh token"}, http.StatusBadRequest)
			return
		}
		h.Logger.Info().
			Str("identifier", identifier).
			Str("provider", providerName).
			Msg("Successfully found user by refresh token")

		newRefreshToken, newAccessToken, err := provider.ValidateRefreshToken(refreshReq.RefreshToken, identifier)
		if err != nil {
			h.Logger.Error().
				Err(err).
				Str("identifier", identifier).
				Str("provider", providerName).
				Msg("Failed to validate refresh token")
			res.Json(w, map[string]string{"error": "Invalid or expired refresh token"}, http.StatusBadRequest)
			return
		}

		// MODIFIED: Save new refresh token if provided
		if newRefreshToken != "" {
			err = h.TokenStorage.SaveToken(identifier, providerName, newRefreshToken)
			if err != nil {
				h.Logger.Error().
					Err(err).
					Str("identifier", identifier).
					Str("provider", providerName).
					Msg("Failed to save new refresh token")
				res.Json(w, map[string]string{"error": "Failed to save new refresh token"}, http.StatusInternalServerError)
				return
			}
			h.Logger.Info().
				Str("identifier", identifier).
				Str("provider", providerName).
				Str("new_refresh_token", newRefreshToken[:10]+"...").
				Msg("Saved new refresh token")
		}

		response := AccessResponse{
			AccessToken:  newAccessToken,
			RefreshToken: newRefreshToken, // Empty if not updated
			Provider:     providerName,
		}
		res.Json(w, response, http.StatusOK)

		h.Logger.Info().Str("identifier", identifier).Str("provider", providerName).Msg("Successfully refreshed provider tokens")
	}
}
