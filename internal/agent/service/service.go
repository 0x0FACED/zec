package service

import (
	"context"
	"sync"
	"time"

	"github.com/0x0FACED/zec/internal/agent/dto"
	"github.com/awnumar/memguard"
)

type ProtectedSession struct {
	fek           *memguard.LockedBuffer
	masterKey     *memguard.LockedBuffer
	containerPath string
	userID        int
	createdAt     time.Time
	expiresAt     time.Time
	lastAccess    time.Time
}

type AgentService struct {
	sessions map[string]*ProtectedSession
	mu       sync.RWMutex
}

func NewAgentService() *AgentService {
	return &AgentService{
		sessions: make(map[string]*ProtectedSession),
	}
}

func (s *AgentService) CreateSession(ctx context.Context, req *dto.CreateSessionRequest) (*dto.CreateSessionResponse, error) {

}

func (s *AgentService) GetFEK(ctx context.Context, req *dto.GetFEKRequest) (*dto.GetFEKResponse, error) {

}

func (s *AgentService) RefreshSession(ctx context.Context, req *dto.RefreshSessionRequest) (*dto.RefreshSessionResponse, error) {

}

func (s *AgentService) CloseSession(ctx context.Context, req *dto.CloseSessionRequest) (*dto.CloseSessionResponse, error) {

}

func (s *AgentService) ListSessions(ctx context.Context, req *dto.ListSessionsRequest) (*dto.ListSessionsResponse, error) {

}
