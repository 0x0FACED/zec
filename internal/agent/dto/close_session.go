package dto

type CloseSessionRequest struct {
	Meta Meta
}

type CloseSessionResponse struct {
	Success bool
	Error   *AgentError
}
