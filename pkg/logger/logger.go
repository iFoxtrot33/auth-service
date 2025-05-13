package logger

import (
	"os"

	configs "AuthService/config"

	"github.com/rs/zerolog"
)

func NewLogger(cfg *configs.Config) *zerolog.Logger {
	zerolog.SetGlobalLevel(zerolog.Level(cfg.Logger.Level))

	var logger zerolog.Logger

	if cfg.Logger.Format == "json" {
		logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	} else {
		consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout}
		logger = zerolog.New(consoleWriter).With().Timestamp().Logger()
	}

	return &logger
}
