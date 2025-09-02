package agent

type AgentError struct {
	Message string `json:"message"`
}

func (e *AgentError) Error() string {
	return e.Message
}
