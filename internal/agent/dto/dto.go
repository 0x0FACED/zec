package dto

import "time"

type Meta struct {
	ContainerPath string
	UserID        string
	MAC           string
}

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

type GetFEKRequest struct {
	Meta Meta
}

type GetFEKResponse struct {
	Success bool
	FEK     []byte
	Found   bool
	Error   *AgentError
}

type RefreshSessionRequest struct {
	Meta             Meta
	ExtendTTLSeconds int32
}

type RefreshSessionResponse struct {
	Success      bool
	NewExpiresAt int64
	Error        *AgentError
}

type CloseSessionRequest struct {
	Meta Meta
}

type CloseSessionResponse struct {
	Success bool
	Error   *AgentError
}

type ListSessionsRequest struct {
	Meta Meta
}

type ListSessionsResponse struct {
	Sessions []*SessionInfo
	Error    *AgentError
}

type SessionInfo struct {
	ContainerPath string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastAccessAt  time.Time
}

type AgentError struct {
	Message string
}
