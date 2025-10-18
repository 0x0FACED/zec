package handler

import (
	"context"
)

// Интерфейс транспортного слоя
type Transport interface {
	Start(ctx context.Context) error
	Stop() error
}
