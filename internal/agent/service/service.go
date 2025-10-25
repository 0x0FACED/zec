package service

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"sync"

	"github.com/0x0FACED/zec/internal/agent/dto"
	"github.com/0x0FACED/zec/internal/agent/session"
	"github.com/0x0FACED/zec/pkg/zec"
)

type AgentService struct {
	sessions map[string]*session.ProtectedSession
	mu       sync.RWMutex
}

func NewAgentService() *AgentService {
	return &AgentService{
		sessions: make(map[string]*session.ProtectedSession),
	}
}

func (s *AgentService) CreateSession(ctx context.Context, req *dto.CreateSessionRequest) (*dto.CreateSessionResponse, error) {
	path := req.Meta.ContainerPath
	meta := req.Meta
	// 1. Узнать, есть ли вообще по этому пути файл с расширением zec
	// 2. Сгенерировать уникальный ключ из данных Meta и пароля (?)
	// 3. Попробовать открыть файл с помощью переданного пароля
	// 4. Если получилось, значит создаем сессию, сохраняем в память FEK и мастер-ключ
	// 5. Возвращаем успех и время жизни сессии

	// Открываем только для чтения, чтобы проверить существование
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return &dto.CreateSessionResponse{
			Success: false,
			Error: &dto.AgentError{
				Message: "Container not found: " + err.Error(),
			},
		}, nil
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return &dto.CreateSessionResponse{
			Success: false,
			Error: &dto.AgentError{
				Message: "Seek to start failed: " + err.Error(),
			},
		}, nil
	}

	header := zec.Header{}

	err = binary.Read(file, binary.LittleEndian, &header)
	if err != nil {
		return &dto.CreateSessionResponse{
			Success: false,
			Error: &dto.AgentError{
				Message: "Failed to read container header: " + err.Error(),
			},
		}, nil
	}

	sess, err := session.NewProtectedSession(req.Password, path, file, &header, meta.UserID)
	if err != nil {
		return &dto.CreateSessionResponse{
			Success: false,
			Error: &dto.AgentError{
				Message: "Failed to create session: " + err.Error(),
			},
		}, nil
	}

	// ну и далее чет делаем, потом допишу
	sessionKey := session.GenerateSessionKey(meta)
	s.mu.Lock()
	s.sessions[sessionKey] = sess
	s.mu.Unlock()

}

func (s *AgentService) GetFEK(ctx context.Context, req *dto.GetFEKRequest) (*dto.GetFEKResponse, error) {

}

func (s *AgentService) RefreshSession(ctx context.Context, req *dto.RefreshSessionRequest) (*dto.RefreshSessionResponse, error) {

}

func (s *AgentService) CloseSession(ctx context.Context, req *dto.CloseSessionRequest) (*dto.CloseSessionResponse, error) {

}

func (s *AgentService) ListSessions(ctx context.Context, req *dto.ListSessionsRequest) (*dto.ListSessionsResponse, error) {

}
