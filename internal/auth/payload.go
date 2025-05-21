package auth

type AccessResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
	RefreshToken string `json:"refresh_token"`
}

type ErrorResponse struct {
	Error string `json:"error" example:"Invalid provider"`
}
