package dto

type CreateSessionRequest struct {
	Meta       Meta
	Password   []byte
	TTLSeconds int32
}

type CreateSessionResponse struct {
	Success   bool
	ExpiresAt int64
	Error     *AgentError
}
