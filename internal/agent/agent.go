package agent

import (
	"sync"
	"time"

	"github.com/0x0FACED/zlog"
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

type Agent struct {
	sessions map[string]*ProtectedSession
	log      *zlog.ZerologLogger
	mu       sync.RWMutex
}

func New(logger *zlog.ZerologLogger) *Agent {
	return &Agent{
		sessions: make(map[string]*ProtectedSession),
		log:      logger,
	}
}

// Agent больше не управляет транспортами
// Это делает внешний код (main или coordinator)

// not implemented yet
func (a *Agent) Status() error {
	return nil
}

// not implemented yet
func (a *Agent) Info() error {
	return nil
}
