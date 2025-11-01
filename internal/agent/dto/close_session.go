package dto

type CloseSessionRequest struct {
	Meta       Meta
	SessionKey string
}

type CloseSessionResponse struct {
	Success bool
	Error   *AgentError
}
