package config

import (
	"fmt"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	Environment string `yaml:"environment"`
	HTTPServer  `yaml:"http_server"`
	Logger      LogConfig  `yaml:"logger"`
	CORS        CORSConfig `yaml:"cors"`
	Auth        AuthConfig
}

type HTTPServer struct {
	Address     string        `yaml:"address" env-default:"localhost:8082"`
	Timeout     time.Duration `yaml:"timeout" env-default:"4s"`
	IdleTimeout time.Duration `yaml:"idle_timeout" env-default:"60s"`
}

type LogConfig struct {
	Level  int    `yaml:"level" env-default:"1"`
	Format string `yaml:"format" env-default:"console"`
}

type CORSConfig struct {
	AllowedOrigins []string `yaml:"allowed_origins"`
}

type AuthConfig struct {
	Google GoogleOAuthConfig `yaml:"google"`
	JWT    JWTConfig         `yaml:"jwt"`
}

type GoogleOAuthConfig struct {
	ClientID     string   `yaml:"client_id" env:"GOOGLE_CLIENT_ID"`
	ClientSecret string   `yaml:"client_secret" env:"GOOGLE_CLIENT_SECRET"`
	RedirectURL  string   `yaml:"redirect_url"`
	Scopes       []string `yaml:"scopes"`
}

type JWTConfig struct {
	Secret           string `yaml:"secret" env:"JWT_SECRET"`
	AccessExpiresIn  int64  `yaml:"access_expires_in"`
	RefreshExpiresIn int64  `yaml:"refresh_expires_in"`
}

func (g *GoogleOAuthConfig) GetOAuthConfig() *oauth2.Config {

	clientID := g.ClientID
	clientSecret := g.ClientSecret

	if envClientID := os.Getenv("GOOGLE_CLIENT_ID"); envClientID != "" {
		clientID = envClientID
	} else {
		fmt.Println("WARNING: GOOGLE_CLIENT_ID not found in environment variables!")
	}

	if envClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET"); envClientSecret != "" {
		clientSecret = envClientSecret
	} else {
		fmt.Println("WARNING: GOOGLE_CLIENT_SECRET not found in environment variables!")
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  g.RedirectURL,
		Scopes:       g.Scopes,
		Endpoint:     google.Endpoint,
	}
}

func (j *JWTConfig) GetSecret() string {
	secret := j.Secret
	if envSecret := os.Getenv("JWT_SECRET"); envSecret != "" {
		secret = envSecret
	}
	return secret
}

func Init() *Config {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config/local.yml"
	}

	_, err := os.Stat(configPath)
	if err != nil && os.IsNotExist(err) {
		panic(fmt.Sprintf("Config file %s does not exist", configPath))
	}

	var cfg Config
	err = cleanenv.ReadConfig(configPath, &cfg)
	if err != nil {
		panic(fmt.Sprintf("Failed to read config file: %s", err))
	}

	envFile := ".env"
	if cfg.Environment == "local" {
		envFile = ".env.local"
	} else if cfg.Environment == "production" {
		envFile = ".env.production"
	}

	if err := godotenv.Load(envFile); err != nil {
		fmt.Printf("No %s file found\n", envFile)
	}

	authConfigPath := os.Getenv("AUTH_CONFIG_PATH")
	if authConfigPath == "" {
		authConfigPath = "config/auth_config_local.yml"
	}

	_, err = os.Stat(authConfigPath)
	if err != nil && os.IsNotExist(err) {
		return &cfg
	}

	var authCfg AuthConfig
	err = cleanenv.ReadConfig(authConfigPath, &authCfg)
	if err != nil {
		panic(fmt.Sprintf("Failed to read auth config file: %s", err))
	}

	cfg.Auth = authCfg

	_ = cfg.Auth.Google.GetOAuthConfig()
	_ = cfg.Auth.JWT.GetSecret()

	return &cfg
}
