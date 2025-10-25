package dto

type GetFEKRequest struct {
	Meta Meta
}

type GetFEKResponse struct {
	Success bool
	FEK     []byte
	Found   bool
	Error   *AgentError
}
