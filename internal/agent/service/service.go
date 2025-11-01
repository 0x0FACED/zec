package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
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

	sess, err := session.NewProtectedSession(req.Password, file, &header, meta)
	if err != nil {
		return &dto.CreateSessionResponse{
			Success: false,
			Error: &dto.AgentError{
				Message: "Failed to create session: " + err.Error(),
			},
		}, nil
	}

	// TODO: возможно вообще привязать сертификат mTLS к сессии
	// есть ли смысл делать это методом сервиса?
	sessionKey := s.generateSessionKey(meta, sess)
	s.mu.Lock()
	s.sessions[sessionKey] = sess
	s.mu.Unlock()

	return &dto.CreateSessionResponse{
		Success:   true,
		ExpiresAt: sess.ExpiresAt().Unix(),
	}, nil
}

func (s *AgentService) generateSessionKey(meta dto.Meta, sess *session.ProtectedSession) string {
	// TOOD: убрать этот МК и генерирорвать при запуске агента свой МК, который храниться будет в temp файле с правами 600.
	masterKey, err := sess.MasterKey()
	if err != nil {
		return ""
	}

	data := []byte(meta.ContainerPath + meta.UserID + meta.MAC)
	hmac := sessionHmac(masterKey, data)

	return fmt.Sprintf("%x", hmac)
}

// ну как костыль пока что
func sessionHmac(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)

	h.Write([]byte("zec-agent-session"))
	h.Write(data)

	return h.Sum(nil)
}

func (s *AgentService) GetFEK(ctx context.Context, req *dto.GetFEKRequest) (*dto.GetFEKResponse, error) {
	// раз уж у меня передается Meta, то можно проверить что сессия принадлежит этой мете
	s.mu.RLock()
	sess, exists := s.sessions[req.SessionKey]
	s.mu.RUnlock()
	if !exists {
		return &dto.GetFEKResponse{
			Success: false,
			Error: &dto.AgentError{
				Message: "Session not found",
			},
		}, nil
	}

	fek, err := sess.FEK()
	if err != nil {
		return &dto.GetFEKResponse{
			Success: false,
			Error: &dto.AgentError{
				Message: "Failed to retrieve FEK: " + err.Error(),
			},
		}, nil
	}

	return &dto.GetFEKResponse{
		Success: true,
		FEK:     fek,
	}, nil
}

func (s *AgentService) RefreshSession(ctx context.Context, req *dto.RefreshSessionRequest) (*dto.RefreshSessionResponse, error) {

}

func (s *AgentService) CloseSession(ctx context.Context, req *dto.CloseSessionRequest) (*dto.CloseSessionResponse, error) {

}

func (s *AgentService) ListSessions(ctx context.Context, req *dto.ListSessionsRequest) (*dto.ListSessionsResponse, error) {

}
