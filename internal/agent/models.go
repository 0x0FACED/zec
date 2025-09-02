package agent

import (
	"encoding/json"
	"time"
)

type Command string

const (
	CmdCreateSession  Command = "create_session"
	CmdGetFEK         Command = "get_fek"
	CmdRefreshSession Command = "refresh_session"
	CmdCloseSession   Command = "close_session"
	CmdListSessions   Command = "list_sessions"
)

type IPCMessage struct {
	Type string          `json:"type"`
	Meta Meta            `json:"meta"`
	Data json.RawMessage `json:"data"`
}

type Meta struct {
	ContainerPath string `json:"container_path"` // path to the encrypted container
	UserID        string `json:"user_id"`        // os.Getuid() as string
	Mac           string `json:"mac"`            // mac address of the interface where the request comes from
}

type CreateSessionRequest struct {
	Password []byte `json:"password"`
	TTL      int    `json:"ttl_seconds"`
}

type CreateSessionResponse struct {
	Success   bool       `json:"success"`
	ExpiresAt int64      `json:"expires_at,omitempty"`
	Error     AgentError `json:"error,omitempty"`
}

// empty request
type GetFEKRequest struct {
}

type GetFEKResponse struct {
	Success bool       `json:"success"`
	FEK     [32]byte   `json:"fek,omitempty"`
	Found   bool       `json:"found,omitempty"`
	Error   AgentError `json:"error,omitempty"`
}

type RefreshSessionRequest struct {
	ExtendTTL int `json:"extend_ttl_seconds"`
}

type RefreshSessionResponse struct {
	Success bool       `json:"success"`
	Error   AgentError `json:"error,omitempty"`
}

type CloseSessionRequest struct {
}

type CloseSessionResponse struct {
	Success bool       `json:"success"`
	Error   AgentError `json:"error,omitempty"`
}

type ListSessionsRequest struct {
	// empty
}

type ListSessionsResponse struct {
	Sessions []SessionInfo `json:"sessions,omitempty"`
	Error    AgentError    `json:"error,omitempty"`
}

type SessionInfo struct {
	ContainerPath string    `json:"container_path"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	LastAccessAt  time.Time `json:"last_access_at"`
}
