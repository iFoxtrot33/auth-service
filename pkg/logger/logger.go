package logger

import (
	"os"

	configs "AuthService/config"

	"github.com/rs/zerolog"
)

type Logger = zerolog.Logger

func NewLogger(cfg *configs.Config) *Logger {
	zerolog.SetGlobalLevel(zerolog.Level(cfg.Logger.Level))

	var logger Logger

	if cfg.Logger.Format == "json" {
		logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	} else {
		consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout}
		logger = zerolog.New(consoleWriter).With().Timestamp().Logger()
	}

	return &logger
}
