package auth

type AccessResponse struct {
	AccessToken string `json:"access_token"`
}

type ErrorResponse struct {
	Error string `json:"error" example:"Invalid provider"`
}
