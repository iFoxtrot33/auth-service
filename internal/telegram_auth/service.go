package telegram_auth

import (
	"AuthService/config"
	"AuthService/pkg/types"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

type TelegramProvider struct {
	config *config.TelegramOAuthConfig
	logger *zerolog.Logger
	isBot  bool
}

func NewTelegramProvider(cfg *config.Config, logger *zerolog.Logger, isBot bool) *TelegramProvider {

	return &TelegramProvider{
		config: &cfg.Auth.Telegram,
		logger: logger,
		isBot:  isBot,
	}
}

func (t *TelegramProvider) GetAuthURL(state string) string {
	if state == "" {
		t.logger.Error().Msg("Empty state provided for Telegram URL")
		return ""
	}
	t.logger.Info().Msg("Generating Telegram URL")
	var url string
	if t.isBot {
		// TODO: Add bot name when will be ready
		url = fmt.Sprintf("https://t.me/@<BOT_NAME>?start=%s", state)
	} else {
		url = fmt.Sprintf("%s?state=%s", t.config.RedirectURL, state)
	}
	t.logger.Info().Str("auth_url", url).Msg("Generated Telegram URL")
	return url
}

func (t *TelegramProvider) Authenticate(code string) (types.UserInfo, *oauth2.Token, error) {
	if code == "" {
		t.logger.Error().Msg("Empty code provided for Telegram authentication")
		return types.UserInfo{}, nil, errors.New("empty code")
	}

	if t.isBot {
		return t.authenticateBot(code)
	}
	return t.authenticateWidget(code)
}

func (t *TelegramProvider) authenticateBot(code string) (types.UserInfo, *oauth2.Token, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates", t.config.Token), nil)
	if err != nil {
		t.logger.Error().Err(err).Msg("Failed to create request to Telegram API")
		return types.UserInfo{}, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		t.logger.Error().Err(err).Msg("Failed to request Telegram API")
		return types.UserInfo{}, nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Ok     bool `json:"ok"`
		Result []struct {
			Message struct {
				From struct {
					ID        int64  `json:"id"`
					Username  string `json:"username"`
					FirstName string `json:"first_name"`
				} `json:"from"`
				Text string `json:"text"`
			} `json:"message"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.logger.Error().Err(err).Msg("Failed to decode Telegram response")
		return types.UserInfo{}, nil, err
	}

	if !result.Ok || len(result.Result) == 0 {
		t.logger.Error().Msg("No data from Telegram API")
		return types.UserInfo{}, nil, errors.New("no data from bot")
	}

	var userInfo types.UserInfo
	for _, update := range result.Result {
		if strings.Contains(update.Message.Text, "/start "+code) {

			userInfo.ID = fmt.Sprintf("%d", update.Message.From.ID)
			userInfo.Name = update.Message.From.FirstName
			if update.Message.From.Username != "" {
				userInfo.Email = update.Message.From.Username
			} else {
				userInfo.Email = userInfo.ID
				t.logger.Info().
					Str("id", userInfo.ID).
					Msg("Using Telegram ID as identifier due to empty username")
			}
			break
		}
	}

	if userInfo.ID == "" {
		t.logger.Error().Msg("User not found or invalid state")
		return types.UserInfo{}, nil, errors.New("invalid state")
	}

	token := &oauth2.Token{
		AccessToken:  fmt.Sprintf("bot_%s", userInfo.ID),
		TokenType:    "Bearer",
		RefreshToken: "",
	}

	t.logger.Info().
		Str("identifier", userInfo.Email).
		Str("telegram_id", userInfo.ID).
		Msg("Successfully retrieved Telegram bot user info")
	return userInfo, token, nil
}

func (t *TelegramProvider) authenticateWidget(code string) (types.UserInfo, *oauth2.Token, error) {

	params, err := url.ParseQuery(code)
	if err != nil {
		t.logger.Error().Err(err).Msg("Failed to parse Telegram parameters")
		return types.UserInfo{}, nil, err
	}

	if !t.verifyTelegramData(params) {
		t.logger.Error().Msg("Invalid Telegram data signature")
		return types.UserInfo{}, nil, errors.New("invalid signature")
	}

	userInfo := types.UserInfo{
		ID:   params.Get("id"),
		Name: params.Get("first_name"),
	}
	if params.Get("username") != "" {
		userInfo.Email = params.Get("username")
	} else {
		userInfo.Email = userInfo.ID
		t.logger.Info().
			Str("id", userInfo.ID).
			Msg("Using Telegram ID as identifier due to empty username")
	}

	// Создаём фейковый токен с hash
	token := &oauth2.Token{
		AccessToken:  params.Get("hash"),
		TokenType:    "Bearer",
		RefreshToken: "",
	}

	t.logger.Info().
		Str("identifier", userInfo.Email).
		Str("telegram_id", userInfo.ID).
		Msg("Successfully retrieved Telegram widget user info")
	return userInfo, token, nil
}

func (t *TelegramProvider) ValidateRefreshToken(refreshToken, expectedIdentifier string) (string, error) {
	t.logger.Error().Msg("Telegram does not support refresh token")
	return "", errors.New("refresh token not supported")
}

func (t *TelegramProvider) verifyTelegramData(params url.Values) bool {
	receivedHash := params.Get("hash")
	if receivedHash == "" {
		return false
	}

	var dataCheck []string
	for key, values := range params {
		if key != "hash" {
			dataCheck = append(dataCheck, fmt.Sprintf("%s=%s", key, values[0]))
		}
	}
	sort.Strings(dataCheck)
	dataCheckString := strings.Join(dataCheck, "\n")

	secretKey := sha256.Sum256([]byte(t.config.Token))
	h := hmac.New(sha256.New, secretKey[:])
	h.Write([]byte(dataCheckString))
	computedHash := fmt.Sprintf("%x", h.Sum(nil))

	return computedHash == receivedHash
}
