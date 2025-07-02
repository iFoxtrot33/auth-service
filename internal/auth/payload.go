package auth

type CallbackResponse struct {
	SessionID string `json:"session_id"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
