package dto

import "time"

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
