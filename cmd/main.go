package main

import (
	"AuthService/config"
	"AuthService/internal/auth"
	"AuthService/internal/telemetry"
	"AuthService/pkg/jwt"
	"AuthService/pkg/kafka"
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

	//Setup Kafka Producer
	kafkaProducer := kafka.NewProducer(kafka.ProducerConfig{
		Brokers:      cfg.Kafka.Brokers,
		Topic:        cfg.Kafka.AuthTopic,
		WriteTimeout: cfg.Kafka.Timeout.Write,
		ReadTimeout:  cfg.Kafka.Timeout.Read,
		Logger:       *log,
	})
	defer func() {
		if err := kafkaProducer.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close Kafka producer")
		}
	}()

	//JWT Service
	jwtService := jwt.NewJWT(cfg)

	// Setting up router
	router := http.NewServeMux()

	// Swagger
	swagger.SetupSwagger(router)

	//Middlewares
	stack := middleware.Chain(
		middleware.Logging(log),
		middleware.CORS(cfg.CORS.AllowedOrigins),
	)

	// Provider Factory
	providerFactory := auth.NewProviderFactory(cfg, log)

	//Handlers
	auth.NewAuthHandler(router, &auth.AuthHandlerDeps{
		Config:          cfg,
		Logger:          log,
		ProviderFactory: providerFactory,
		KafkaProducer:   kafkaProducer,
		JWTService:      jwtService,
	})

	//Telemetry
	metricsService := telemetry.NewMetricsService()
	err := telemetry.NewHealthHandler(router, *log, metricsService)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize telemetry")
	}

	server := &http.Server{
		Addr:         cfg.Address,
		Handler:      stack(router),
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}

	log.Info().Msgf("Server starting on %s", cfg.Address)

	err = server.ListenAndServe()

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
