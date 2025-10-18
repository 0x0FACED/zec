// TOOD: Remove
package agent

import (
	"context"
	"sync"

	"github.com/0x0FACED/zec/internal/agent/handler"
	"github.com/0x0FACED/zlog"
)

type Orchestrator struct {
	transports []handler.Transport
	log        *zlog.ZerologLogger
}

func NewOrchestrator(logger *zlog.ZerologLogger, transports ...handler.Transport) *Orchestrator {
	return &Orchestrator{
		transports: transports,
		log:        logger,
	}
}

func (c *Orchestrator) Start(ctx context.Context) error {
	c.log.Info().Int("count", len(c.transports)).Msg("Starting transports...")

	var wg sync.WaitGroup
	errCh := make(chan error, len(c.transports))

	// Запускаем все транспорты
	for i, transport := range c.transports {
		wg.Add(1)
		go func(idx int, t handler.Transport) {
			defer wg.Done()

			c.log.Info().Int("transport_index", idx).Msg("Starting transport")

			if err := t.Start(ctx); err != nil {
				c.log.Error().
					Int("transport_index", idx).
					Err(err).
					Msg("Transport failed")
				errCh <- err
			}
		}(i, transport)
	}

	<-ctx.Done()
	c.log.Info().Msg("Shutting down transports...")

	return c.Stop()
}

func (c *Orchestrator) Stop() error {
	var lastErr error

	for i, transport := range c.transports {
		if err := transport.Stop(); err != nil {
			c.log.Error().
				Int("transport_index", i).
				Err(err).
				Msg("Failed to stop transport")
			lastErr = err
		}
	}

	return lastErr
}
