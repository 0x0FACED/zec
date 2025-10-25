package dto

type RefreshSessionRequest struct {
	Meta             Meta
	ExtendTTLSeconds int32
}

type RefreshSessionResponse struct {
	Success      bool
	NewExpiresAt int64
	Error        *AgentError
}
