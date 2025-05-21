package auth

import (
	"AuthService/pkg/jwt"
	"AuthService/pkg/req"
	"AuthService/pkg/res"
	"net/http"
	"time"

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

type JWT interface {
	CreateAccessToken(data jwt.JWTData) (string, error)
	CreateRefreshToken(data jwt.JWTData) (string, error)
	Parse(token string) (jwt.JWTData, error)
}

type AuthHandler struct {
	Logger          Logger
	Config          Config
	JWT             JWT
	ProviderFactory ProviderFactory
	TokenStorage    *TokenStorage
}

type AuthHandlerDeps struct {
	Config          Config
	Logger          Logger
	JWT             JWT
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
		JWT:             deps.JWT,
		ProviderFactory: deps.ProviderFactory,
		TokenStorage:    deps.TokenStorage,
	}

	router.HandleFunc("GET /api/v1/login", handler.handleLogin())
	router.HandleFunc("GET /api/v1/access", handler.handleAccess())
	router.HandleFunc("POST /api/v1/refresh", handler.handleRefresh())
}

// handleLogin initiates OAuth login by redirecting to the provider's auth URL
// @Summary Initiate OAuth login
// @Description Redirects the user to the OAuth provider's authentication URL
// @Tags auth
// @Accept json
// @Produce json
// @Param provider query string true "OAuth provider (e.g., google)"
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

// handleAccess completes OAuth authentication and issues a JWT access token
// @Summary Complete OAuth authentication
// @Description Exchanges the OAuth code for user info and returns a JWT access token
// @Tags auth
// @Accept json
// @Produce json
// @Param provider query string true "OAuth provider (e.g., google)"
// @Param state query string true "OAuth state parameter"
// @Param code query string true "OAuth authorization code"
// @Success 200 {object} AccessResponse "JWT access token"
// @Failure 400 {object} ErrorResponse "Provider not specified, invalid state, or code not specified"
// @Failure 500 {object} ErrorResponse "Authentication failed or failed to create access token"
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

		// Изменение: Используем identifier (email или login)
		identifier := userInfo.Email
		if identifier == "" {
			h.Logger.Warn().
				Str("provider", providerName).
				Msg("User info identifier is empty")
			res.Json(w, map[string]string{"error": "User identifier is empty"}, http.StatusBadRequest)
			return
		}

		accessToken, err := h.JWT.CreateAccessToken(jwt.JWTData{
			Email:    identifier,
			Name:     userInfo.Name,
			Provider: providerName,
		})
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to create access token")
			res.Json(w, map[string]string{"error": "Failed to create access token"}, http.StatusInternalServerError)
			return
		}

		refreshToken, err := h.JWT.CreateRefreshToken(jwt.JWTData{
			Email:    identifier,
			Name:     userInfo.Name,
			Provider: providerName,
		})
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to create refresh token")
			res.Json(w, map[string]string{"error": "Failed to create refresh token"}, http.StatusInternalServerError)
			return
		}

		// Сохраняем OAuth refresh-токен в TokenStorage
		if (providerName == "google" || providerName == "github") && oauthToken.RefreshToken != "" {
			if h.TokenStorage == nil {
				h.Logger.Error().Str("identifier", identifier).Msg("TokenStorage is nil in handleAccess")
				res.Json(w, map[string]string{"error": "Internal server error"}, http.StatusInternalServerError)
				return
			}
			h.Logger.Info().
				Str("identifier", identifier).
				Str("provider", providerName).
				Str("refresh_token", oauthToken.RefreshToken[:10]+"...").
				Msg("Attempting to save OAuth refresh token")
			err = h.TokenStorage.SaveToken(identifier, providerName, oauthToken.RefreshToken)
			if err != nil {
				h.Logger.Error().
					Err(err).
					Str("identifier", identifier).
					Str("provider", providerName).
					Str("refresh_token", oauthToken.RefreshToken[:10]+"...").
					Msg("Failed to save OAuth refresh token")
				res.Json(w, map[string]string{"error": "Failed to save validation token"}, http.StatusInternalServerError)
				return
			}
			h.Logger.Info().Str("identifier", identifier).Str("provider", providerName).Msg("Saved OAuth refresh token to storage")
		}

		res.Json(w, AccessResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}, http.StatusOK)

		h.Logger.Info().Str("identifier", identifier).Str("provider", providerName).Msg("Successfully issued JWT access token")
	}
}

// handleRefresh refreshes JWT access token
// @Summary Refresh JWT token
// @Description Refreshes the access token using a refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} AccessResponse "New JWT access token"
// @Failure 400 {object} ErrorResponse "Invalid refresh token"
// @Failure 500 {object} ErrorResponse "Failed to create new token"
// @Router /api/v1/refresh [post]
func (h *AuthHandler) handleRefresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refreshReq, err := req.HandleBody[RefreshRequest](&w, r)
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to parse refresh request")
			res.Json(w, map[string]string{"error": "Invalid request body"}, http.StatusBadRequest)
			return
		}

		// Проверяем JWT refresh-токен
		data, err := h.JWT.Parse(refreshReq.RefreshToken)
		if err != nil {
			h.Logger.Error().
				Err(err).
				Str("token", refreshReq.RefreshToken[:10]+"...").
				Int64("current_time", time.Now().Unix()).
				Msg("Invalid JWT refresh token")
			res.Json(w, map[string]string{"error": "Invalid or expired refresh token"}, http.StatusBadRequest)
			return
		}

		// Изменение: Используем identifier вместо email
		identifier := data.Email
		if identifier == "" {
			h.Logger.Error().
				Str("provider", data.Provider).
				Msg("JWT data identifier is empty")
			res.Json(w, map[string]string{"error": "Invalid JWT data"}, http.StatusBadRequest)
			return
		}

		h.Logger.Info().
			Str("identifier", identifier).
			Str("provider", data.Provider).
			Int64("current_time", time.Now().Unix()).
			Msg("Parsed JWT refresh token")

		// Валидируем OAuth refresh-токен
		if data.Provider == "google" || data.Provider == "github" {
			if h.TokenStorage == nil {
				h.Logger.Error().Str("identifier", identifier).Msg("TokenStorage is nil in handleRefresh")
				res.Json(w, map[string]string{"error": "Internal server error"}, http.StatusInternalServerError)
				return
			}

			oauthRefreshToken, err := h.TokenStorage.GetToken(identifier, data.Provider)
			if err != nil {
				h.Logger.Warn().
					Err(err).
					Str("identifier", identifier).
					Str("provider", data.Provider).
					Msg("OAuth refresh token not found, skipping validation")
			} else {
				err = ValidateUserWithRefreshToken(h.ProviderFactory, h.Logger, data.Provider, identifier, oauthRefreshToken)
				if err != nil {
					h.Logger.Error().
						Err(err).
						Str("identifier", identifier).
						Str("provider", data.Provider).
						Msg("Failed to validate OAuth refresh token")
					res.Json(w, map[string]string{"error": "Invalid or expired validation token"}, http.StatusBadRequest)
					return
				}
				h.Logger.Info().
					Str("identifier", identifier).
					Str("provider", data.Provider).
					Msg("Successfully validated OAuth refresh token")
			}
		}

		// Создаем новый JWT access-токен
		accessToken, err := h.JWT.CreateAccessToken(jwt.JWTData{
			Email:    identifier,
			Name:     data.Name,
			Provider: data.Provider,
		})
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to create new access token")
			res.Json(w, map[string]string{"error": "Failed to create access token"}, http.StatusInternalServerError)
			return
		}

		// Создаем новый JWT refresh-токен
		refreshToken, err := h.JWT.CreateRefreshToken(jwt.JWTData{
			Email:    identifier,
			Name:     data.Name,
			Provider: data.Provider,
		})
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to create new refresh token")
			res.Json(w, map[string]string{"error": "Failed to create refresh token"}, http.StatusInternalServerError)
			return
		}

		res.Json(w, AccessResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}, http.StatusOK)

		h.Logger.Info().Str("identifier", identifier).Str("provider", data.Provider).Msg("Successfully refreshed tokens")
	}
}
