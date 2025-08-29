package zec

import (
	"crypto/rand"
	"sync"
	"time"
)

// Session представляет активную сессию работы с контейнером
type Session struct {
	mu sync.RWMutex
	// locked buffer memguard
	masterKey [32]byte
	// locked buffer memguard
	fek         [32]byte
	createdAt   time.Time
	accessedAt  time.Time
	isActive    bool
	containerID string

	// Заголовок файла по сути привязан к сессии.
	// Одна сессия - один файл открытый.
	header Header
}

// NewSession создает новую сессию из существующего контейнера (расшифровывает FEK)
func NewSession(containerID string, password []byte, header Header) (*Session, error) {
	masterKey := DeriveKey(password, header.ArgonSalt, header.ArgonMemoryLog2,
		header.ArgonIterations, header.ArgonParallelism)

	fek, err := DecryptFEK(masterKey, header.EncryptedFEK,
		header.VerificationTag, header.AuthenticatedBytes())
	if err != nil {
		return nil, err
	}

	now := time.Now()
	return &Session{
		masterKey:   masterKey,
		fek:         fek,
		createdAt:   now,
		accessedAt:  now,
		isActive:    true,
		containerID: containerID,
		header:      header,
	}, nil
}

// NewSessionForNewContainer создает новую сессию для нового контейнера (генерирует FEK)
func NewSessionForNewContainer(containerID string, password []byte, header Header) (*Session, error) {
	masterKey := DeriveKey(password, header.ArgonSalt, header.ArgonMemoryLog2,
		header.ArgonIterations, header.ArgonParallelism)

	var fek [32]byte
	if _, err := rand.Read(fek[:]); err != nil {
		return nil, err
	}

	encryptedFEK, err := EncryptFEK(fek, masterKey)
	if err != nil {
		return nil, err
	}

	// это в целом просто ужасное решение - изменение хэдера
	// в создании сессии бл. Ну ужас канеш, я это точно перепишу,
	// для удобства пока что так.
	header.EncryptedFEK = encryptedFEK

	now := time.Now()
	session := &Session{
		masterKey:   masterKey,
		fek:         fek,
		createdAt:   now,
		accessedAt:  now,
		isActive:    true,
		containerID: containerID,
		header:      header,
	}

	return session, nil
}

func (s *Session) FEK() [32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accessedAt = time.Now()
	return s.fek
}

func (s *Session) EncryptedFEK() [60]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accessedAt = time.Now()
	return s.header.EncryptedFEK
}

func (s *Session) MasterKey() [32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accessedAt = time.Now()
	return s.masterKey
}

func (s *Session) IsExpired(timeout time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return time.Since(s.accessedAt) > timeout
}

func (s *Session) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.isActive
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.masterKey {
		s.masterKey[i] = 0
	}
	for i := range s.fek {
		s.fek[i] = 0
	}

	s.isActive = false
	return nil
}

func (s *Session) Info() SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return SessionInfo{
		ContainerID: s.containerID,
		CreatedAt:   s.createdAt,
		AccessedAt:  s.accessedAt,
		IsActive:    s.isActive,
	}
}

func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accessedAt = time.Now()
}

func (s *Session) SetHeader(header Header) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.header = header
}

type SessionInfo struct {
	ContainerID string
	CreatedAt   time.Time
	AccessedAt  time.Time
	IsActive    bool
}

// SessionManager управляет множественными сессиями (вот эта темка для агента пойдет уже)
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	timeout  time.Duration
}

func NewSessionManager(timeout time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		timeout:  timeout,
	}

	go sm.cleanupLoop()

	return sm
}

func (sm *SessionManager) CreateSession(sessionID, containerID string, password []byte, header Header) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if existingSession, exists := sm.sessions[sessionID]; exists {
		return nil, existingSession.Close()
	}

	session, err := NewSession(containerID, password, header)
	if err != nil {
		return nil, err
	}
	sm.sessions[sessionID] = session

	return session, nil
}

func (sm *SessionManager) GetSession(sessionID string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, false
	}

	if session.IsExpired(sm.timeout) {
		// ниче не делаем, ибо cleanup сам удалит
		return nil, false
	}

	return session, true
}

func (sm *SessionManager) CloseSession(sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return ErrSessionNotFound
	}

	err := session.Close()
	delete(sm.sessions, sessionID)

	return err
}

func (sm *SessionManager) ListSessions() []SessionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var sessions []SessionInfo
	for _, session := range sm.sessions {
		if session.IsActive() && !session.IsExpired(sm.timeout) {
			sessions = append(sessions, session.Info())
		}
	}

	return sessions
}

func (sm *SessionManager) CloseAllSessions() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var lastErr error
	for sessionID, session := range sm.sessions {
		if err := session.Close(); err != nil {
			lastErr = err
		}
		delete(sm.sessions, sessionID)
	}

	return lastErr
}

func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.cleanupExpiredSessions()
	}
}

func (sm *SessionManager) cleanupExpiredSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var toDelete []string

	for sessionID, session := range sm.sessions {
		if session.IsExpired(sm.timeout) {
			session.Close()
			toDelete = append(toDelete, sessionID)
		}
	}

	for _, sessionID := range toDelete {
		delete(sm.sessions, sessionID)
	}
}

func (sm *SessionManager) SetTimeout(timeout time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.timeout = timeout
}

func (sm *SessionManager) Timeout() time.Duration {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.timeout
}
