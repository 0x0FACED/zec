package agent

import (
	"context"
	"encoding/json"
	"net"
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

func (a *Agent) Start(ctx context.Context) error {
	a.log.Info().Msg("Starting agent listener...")

	li, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: "/tmp/zec-agent.sock",
		Net:  "unix",
	})
	if err != nil {
		a.log.Error().Err(err).Msg("Failed to start agent listener, exiting...")
		return err
	}
	defer li.Close()

	a.log.Info().Msg("Starting to accept connections...")
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := li.AcceptUnix()
			if err != nil {
				a.log.Error().Err(err).Msg("Failed to accept connection, continuing...")
				continue
			}

			a.log.Info().Str("remote_addr", conn.RemoteAddr().String()).Msg("New connection accepted")

			go a.processConnection(conn)
		}
	}
}

// not implemented yet
func (a *Agent) Stop() error {
	return nil
}

// not implemented yet
func (a *Agent) Status() error {
	return nil
}

// not implemented yet
func (a *Agent) Info() error {
	return nil
}

func (a *Agent) processConnection(c *net.UnixConn) {
	defer c.Close()

	decoder := json.NewDecoder(c)
	encoder := json.NewEncoder(c)

	var msg IPCMessage
	if err := decoder.Decode(&msg); err != nil {
		return
	}

	a.log.Info().Any("msg", msg).Msg("Received message")

	switch Command(msg.Type) {
	case CmdCreateSession:
		a.handleCreateSession(msg, encoder)
	case CmdGetFEK:
		a.handleGetFEK(msg, encoder)
	case CmdRefreshSession:
		a.handleRefreshSession(msg, encoder)
	case CmdCloseSession:
		a.handleCloseSession(msg, encoder)
	case CmdListSessions:
		a.handleListSessions(msg, encoder)
	default:
		a.handleUnknownCommand(encoder)
	}
}

func (a *Agent) handleCreateSession(msg IPCMessage, encoder *json.Encoder) {
	var req CreateSessionRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		a.log.Error().Err(err).Any("meta", msg.Meta).Msg("Failed to unmarshal CreateSessionRequest")
		err = encoder.Encode(CreateSessionResponse{
			Success:   false,
			ExpiresAt: 0,
			Error:     AgentError{Message: "Invalid request"},
		})
		if err != nil {
			a.log.Error().Err(err).Msg("Failed to send CreateSessionResponse")
		}
		return
	}

}

func (a *Agent) handleGetFEK(msg IPCMessage, encoder *json.Encoder) {

}

func (a *Agent) handleRefreshSession(msg IPCMessage, encoder *json.Encoder) {
	var req RefreshSessionRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		return
	}
}

func (a *Agent) handleCloseSession(msg IPCMessage, encoder *json.Encoder) {

}

func (a *Agent) handleListSessions(msg IPCMessage, encoder *json.Encoder) {

}

func (a *Agent) handleUnknownCommand(encoder *json.Encoder) {

}
