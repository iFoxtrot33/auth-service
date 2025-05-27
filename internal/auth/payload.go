package auth

type AccessResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Provider     string `json:"provider"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
	Provider     string `json:"provider" validate:"required,oneof=google github telegram_bot telegram_widget"`
}

type RefreshResponse struct {
	RefreshToken string `json:"refresh_token"`
}

type ErrorResponse struct {
	Error string `json:"error" example:"Invalid provider"`
}
