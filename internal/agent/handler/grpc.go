package handler

import (
	"context"
	"net"

	"github.com/0x0FACED/zec/internal/agent/dto"
	"github.com/0x0FACED/zec/internal/agent/service"
	gen "github.com/0x0FACED/zec/pkg/gen/api"
	"google.golang.org/grpc"
)

// gRPC транспорт
type GRPCTransport struct {
	server *grpc.Server
}

func NewGRPCTransport(server *grpc.Server) *GRPCTransport {
	return &GRPCTransport{
		server: server,
	}
}

func (gt *GRPCTransport) Start(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = gt.Stop()
	}()

	return gt.server.Serve(l)
}

func (gt *GRPCTransport) Stop() error {
	if gt.server != nil {
		gt.server.GracefulStop()
	}
	return nil
}

// gRPC обработчик с конвертацией
type grpcServiceHandler struct {
	gen.UnimplementedZecAgentServer
	service *service.AgentService
}

func (gh *grpcServiceHandler) CreateSession(ctx context.Context, req *gen.CreateSessionRequest) (*gen.CreateSessionResponse, error) {
	domainReq := &dto.CreateSessionRequest{
		Meta: dto.Meta{
			ContainerPath: req.Meta.ContainerPath,
			UserID:        req.Meta.UserId,
			MAC:           req.Meta.Mac,
		},
		Password:   req.Password,
		TTLSeconds: req.TtlSeconds,
	}

	resp, err := gh.service.CreateSession(ctx, domainReq)
	if err != nil {
		return nil, err
	}

	// Конвертация из доменных типов в gRPC
	grpcResp := &gen.CreateSessionResponse{
		Success:   resp.Success,
		ExpiresAt: resp.ExpiresAt,
	}
	if resp.Error != nil {
		grpcResp.Error = &gen.AgentError{Message: resp.Error.Message}
	}

	return grpcResp, nil
}

func (gh *grpcServiceHandler) GetFEK(ctx context.Context, req *gen.GetFEKRequest) (*gen.GetFEKResponse, error) {
	domainReq := &dto.GetFEKRequest{
		Meta: dto.Meta{
			ContainerPath: req.Meta.ContainerPath,
			UserID:        req.Meta.UserId,
			MAC:           req.Meta.Mac,
		},
	}

	resp, err := gh.service.GetFEK(ctx, domainReq)
	if err != nil {
		return nil, err
	}

	grpcResp := &gen.GetFEKResponse{
		Success: resp.Success,
		Fek:     resp.FEK,
		Found:   resp.Found,
	}
	if resp.Error != nil {
		grpcResp.Error = &gen.AgentError{Message: resp.Error.Message}
	}

	return grpcResp, nil
}

func (gh *grpcServiceHandler) RefreshSession(ctx context.Context, req *gen.RefreshSessionRequest) (*gen.RefreshSessionResponse, error) {
	domainReq := &dto.RefreshSessionRequest{
		Meta: dto.Meta{
			ContainerPath: req.Meta.ContainerPath,
			UserID:        req.Meta.UserId,
			MAC:           req.Meta.Mac,
		},
		ExtendTTLSeconds: req.ExtendTtlSeconds,
	}

	resp, err := gh.service.RefreshSession(ctx, domainReq)
	if err != nil {
		return nil, err
	}

	grpcResp := &gen.RefreshSessionResponse{
		Success:      resp.Success,
		NewExpiresAt: resp.NewExpiresAt,
	}
	if resp.Error != nil {
		grpcResp.Error = &gen.AgentError{Message: resp.Error.Message}
	}

	return grpcResp, nil
}

func (gh *grpcServiceHandler) CloseSession(ctx context.Context, req *gen.CloseSessionRequest) (*gen.CloseSessionResponse, error) {
	domainReq := &dto.CloseSessionRequest{
		Meta: dto.Meta{
			ContainerPath: req.Meta.ContainerPath,
			UserID:        req.Meta.UserId,
			MAC:           req.Meta.Mac,
		},
	}

	resp, err := gh.service.CloseSession(ctx, domainReq)
	if err != nil {
		return nil, err
	}

	grpcResp := &gen.CloseSessionResponse{
		Success: resp.Success,
	}
	if resp.Error != nil {
		grpcResp.Error = &gen.AgentError{Message: resp.Error.Message}
	}

	return grpcResp, nil
}

func (gh *grpcServiceHandler) ListSessions(ctx context.Context, req *gen.ListSessionsRequest) (*gen.ListSessionsResponse, error) {
	domainReq := &dto.ListSessionsRequest{
		Meta: dto.Meta{
			ContainerPath: req.Meta.ContainerPath,
			UserID:        req.Meta.UserId,
			MAC:           req.Meta.Mac,
		},
	}

	resp, err := gh.service.ListSessions(ctx, domainReq)
	if err != nil {
		return nil, err
	}

	grpcResp := &gen.ListSessionsResponse{}

	for _, session := range resp.Sessions {
		grpcResp.Sessions = append(grpcResp.Sessions, &gen.SessionInfo{
			ContainerPath: session.ContainerPath,
			CreatedAt:     session.CreatedAt.Unix(),
			ExpiresAt:     session.ExpiresAt.Unix(),
			LastAccessAt:  session.LastAccessAt.Unix(),
		})
	}

	if resp.Error != nil {
		grpcResp.Error = &gen.AgentError{Message: resp.Error.Message}
	}

	return grpcResp, nil
}
