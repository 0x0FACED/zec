package agent

import (
	"context"

	"github.com/0x0FACED/zec/internal/agent/handler"
	"github.com/0x0FACED/zlog"
)

type Agent struct {
	server handler.Transport
	log    *zlog.ZerologLogger
}

func New(server handler.Transport, logger *zlog.ZerologLogger) *Agent {
	return &Agent{
		server: server,
		log:    logger,
	}
}

func (a *Agent) Start(ctx context.Context) error {
	a.log.Info().Msg("Agent started")
	return a.server.Start(ctx)
}

// not implemented yet
func (a *Agent) Status() error {
	return nil
}

// not implemented yet
func (a *Agent) Info() error {
	return nil
}
