package logger

import (
	"AuthService/config"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func createTestConfig(format string, level int) *config.Config {
	return &config.Config{
		Logger: config.LogConfig{
			Format: format,
			Level:  level,
		},
	}
}

func TestNewLogger_JSONFormat(t *testing.T) {
	cfg := createTestConfig("json", 1)
	logger := NewLogger(cfg)

	assert.NotNil(t, logger)
	assert.Equal(t, zerolog.Level(1), zerolog.GlobalLevel())
}

func TestNewLogger_ConsoleFormat(t *testing.T) {
	cfg := createTestConfig("console", 0)
	logger := NewLogger(cfg)

	assert.NotNil(t, logger)
	assert.Equal(t, zerolog.Level(0), zerolog.GlobalLevel())
}

func TestNewLogger_DefaultFormat(t *testing.T) {
	cfg := createTestConfig("", 2)
	logger := NewLogger(cfg)

	assert.NotNil(t, logger)
	assert.Equal(t, zerolog.Level(2), zerolog.GlobalLevel())
}
