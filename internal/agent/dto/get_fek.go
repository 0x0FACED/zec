package dto

type GetFEKRequest struct {
	Meta       Meta
	SessionKey string
}

type GetFEKResponse struct {
	Success bool
	FEK     []byte
	Found   bool
	Error   *AgentError
}
