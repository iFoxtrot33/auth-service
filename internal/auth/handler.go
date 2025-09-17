package auth

import (
	"AuthService/pkg/jwt"
	"AuthService/pkg/kafka"
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
	KafkaProducer   kafka.Producer
	JWTService      *jwt.JWT
}

type AuthHandlerDeps struct {
	Config          Config
	Logger          Logger
	ProviderFactory ProviderFactory
	KafkaProducer   kafka.Producer
	JWTService      *jwt.JWT
}

// NewAuthHandler creates a new auth handler and registers routes
// @Summary Create authentication handler
// @Description Initializes the authentication handler and registers all API routes
func NewAuthHandler(router *http.ServeMux, deps *AuthHandlerDeps) {
	handler := &AuthHandler{
		Logger:          deps.Logger,
		Config:          deps.Config,
		ProviderFactory: deps.ProviderFactory,
		KafkaProducer:   deps.KafkaProducer,
		JWTService:      deps.JWTService,
	}

	router.HandleFunc("GET /api/v1/login", handler.handleLogin())
	router.HandleFunc("GET /api/v1/callback", handler.handleCallback())
	router.HandleFunc("POST /api/v1/logout", handler.handleLogout())
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
// @Success 200 {object} CallbackResponse "Provider access and refresh tokens with provider name"
// @Failure 400 {object} ErrorResponse "Provider not specified, invalid state, code not specified, or user identifier is empty"
// @Failure 500 {object} ErrorResponse "Authentication failed or failed to save tokens"
// @Router /api/v1/callback [get]
func (h *AuthHandler) handleCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

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

		sessionID, err := h.JWTService.CreateSessionID(jwt.JWTData{
			Email:    userInfo.Email,
			Name:     userInfo.Name,
			Provider: providerName,
		})
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to create session ID")
			res.Json(w, ErrorResponse{Error: "Failed to generate session"}, http.StatusInternalServerError)
			return
		}

		// Prepare provider tokens for Kafka
		var providerTokens *kafka.ProviderTokens
		if oauthToken != nil {
			providerTokens = &kafka.ProviderTokens{
				AccessToken:  oauthToken.AccessToken,
				RefreshToken: oauthToken.RefreshToken,
			}
			if !oauthToken.Expiry.IsZero() {
				providerTokens.ExpiresAt = &oauthToken.Expiry
			}
		}

		// Send authentication event to Kafka (Core Service)
		err = h.KafkaProducer.SendUserAuthenticated(ctx, userInfo.Email, providerName, sessionID, providerTokens)
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to send authentication message to Kafka")
			// Don't fail the request - log error and continue
		}

		// Clear OAuth state cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})

		// Return SessionID to user
		response := CallbackResponse{
			SessionID: sessionID,
		}
		res.Json(w, response, http.StatusOK)

		h.Logger.Info().
			Str("email", userInfo.Email).
			Str("provider", providerName).
			Msg("Successfully created session")

	}
}

func (h *AuthHandler) handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
	}
}
