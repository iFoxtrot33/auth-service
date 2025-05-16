package auth

import (
	"AuthService/config"
	"AuthService/pkg/jwt"
	"AuthService/pkg/res"
	"net/http"

	"github.com/rs/zerolog"
)

type AuthHandler struct {
	Logger          *zerolog.Logger
	Config          *config.Config
	JWT             *jwt.JWT
	ProviderFactory ProviderFactory
}

type AuthHandlerDeps struct {
	Config          *config.Config
	Logger          *zerolog.Logger
	JWT             *jwt.JWT
	ProviderFactory ProviderFactory
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
			Secure:   h.Config.Environment == "production",
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

		userInfo, _, err := provider.Authenticate(code)
		if err != nil {
			h.Logger.Error().Err(err).Str("provider", providerName).Msg("Failed to authenticate")
			res.Json(w, map[string]string{"error": "Authentication failed"}, http.StatusInternalServerError)
			return
		}

		accessToken, err := h.JWT.CreateAccessToken(jwt.JWTData{
			Email: userInfo.Email,
			Name:  userInfo.Name,
		})
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to create access token")
			res.Json(w, map[string]string{"error": "Failed to create access token"}, http.StatusInternalServerError)
			return
		}

		res.Json(w, AccessResponse{
			AccessToken: accessToken,
		}, http.StatusOK)

		h.Logger.Info().Str("email", userInfo.Email).Msg("Successfully issued JWT access token")
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
		res.Json(w, map[string]string{"message": "Refresh token"}, http.StatusOK)
	}
}
