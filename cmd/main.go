package main

import (
	"AuthService/config"
	"AuthService/pkg/logger"
	"net/http"
)

func main() {
	//Config
	cfg := config.Init()

	// Setting up router
	router := http.NewServeMux()

	//Logger
	log := logger.NewLogger(cfg)
	log.Info().Msg("Application started")
	log.Info().Msg("Environment: " + cfg.Environment)

	server := &http.Server{
		Addr:    cfg.Address,
		Handler: router,
	}

	log.Info().Msgf("Server starting on %s", cfg.Address)

	err := server.ListenAndServe()

	if err != nil {
		log.Fatal().
			Err(err).
			Msg("Failed to start the HTTP server due to an error")
	}
}
