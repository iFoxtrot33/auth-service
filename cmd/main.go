package main

import (
	"AuthService/config"
	"AuthService/internal/auth"
	"AuthService/pkg/jwt"
	"AuthService/pkg/logger"
	"AuthService/pkg/middleware"
	"AuthService/pkg/swagger"
	"net/http"
	"runtime/debug"

	"github.com/rs/zerolog/log"
)

// @title Auth Service API
// @version 1.0

func main() {
	defer panicRecover()

	//Config
	cfg := config.Init()

	//Logger
	log := logger.NewLogger(cfg)
	log.Info().Msg("Application started")
	log.Info().Msg("Environment: " + cfg.Environment)

	// Setting up router
	router := http.NewServeMux()

	// Swagger
	swagger.SetupSwagger(router)

	//Middlewares
	stack := middleware.Chain(
		middleware.Logging(log),
		middleware.CORS(cfg.CORS.AllowedOrigins),
	)

	// JWT Service
	jwtService := jwt.NewJWT(cfg)

	// Provider Factory
	providerFactory := auth.NewProviderFactory(cfg, log)

	//Handlers
	auth.NewAuthHandler(router, &auth.AuthHandlerDeps{
		Config:          cfg,
		Logger:          log,
		JWT:             jwtService,
		ProviderFactory: providerFactory,
	})

	server := &http.Server{
		Addr:         cfg.Address,
		Handler:      stack(router),
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}

	log.Info().Msgf("Server starting on %s", cfg.Address)

	err := server.ListenAndServe()

	if err != nil {
		log.Fatal().
			Err(err).
			Msg("Failed to start the HTTP server due to an error")
	}

}

func panicRecover() {

	if err := recover(); err != nil {
		log.Error().
			Interface("error", err).
			Str("stack", string(debug.Stack())).
			Msg("Panic recovered in main")
		panic(err)
	}

}
