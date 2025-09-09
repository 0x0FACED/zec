package handler

import (
	"context"
	"net"

	gen "github.com/0x0FACED/zec/pkg/gen/api"
	"google.golang.org/grpc"
)

// gRPC транспорт
type GRPCTransport struct {
	handler Handler
	server  *grpc.Server
	address string
}

func NewGRPCTransport(handler Handler, address string) *GRPCTransport {
	return &GRPCTransport{
		handler: handler,
		address: address,
	}
}

func (gt *GRPCTransport) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", gt.address)
	if err != nil {
		return err
	}

	gt.server = grpc.NewServer()
	grpcHandler := &grpcServiceHandler{handler: gt.handler}
	gen.RegisterZecAgentServer(gt.server, grpcHandler)

	go func() {
		<-ctx.Done()
		gt.server.GracefulStop()
	}()

	return gt.server.Serve(lis)
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
	handler Handler
}

func (gh *grpcServiceHandler) CreateSession(ctx context.Context, req *gen.CreateSessionRequest) (*gen.CreateSessionResponse, error) {
	// Конвертация из gRPC типов в доменные
	domainReq := &CreateSessionRequest{
		Meta: Meta{
			ContainerPath: req.Meta.ContainerPath,
			UserID:        req.Meta.UserId,
			MAC:           req.Meta.Mac,
		},
		Password:   req.Password,
		TTLSeconds: req.TtlSeconds,
	}

	resp, err := gh.handler.CreateSession(ctx, domainReq)
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
	domainReq := &GetFEKRequest{
		Meta: Meta{
			ContainerPath: req.Meta.ContainerPath,
			UserID:        req.Meta.UserId,
			MAC:           req.Meta.Mac,
		},
	}

	resp, err := gh.handler.GetFEK(ctx, domainReq)
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
	domainReq := &RefreshSessionRequest{
		Meta: Meta{
			ContainerPath: req.Meta.ContainerPath,
			UserID:        req.Meta.UserId,
			MAC:           req.Meta.Mac,
		},
		ExtendTTLSeconds: req.ExtendTtlSeconds,
	}

	resp, err := gh.handler.RefreshSession(ctx, domainReq)
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
	domainReq := &CloseSessionRequest{
		Meta: Meta{
			ContainerPath: req.Meta.ContainerPath,
			UserID:        req.Meta.UserId,
			MAC:           req.Meta.Mac,
		},
	}

	resp, err := gh.handler.CloseSession(ctx, domainReq)
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
	domainReq := &ListSessionsRequest{
		Meta: Meta{
			ContainerPath: req.Meta.ContainerPath,
			UserID:        req.Meta.UserId,
			MAC:           req.Meta.Mac,
		},
	}

	resp, err := gh.handler.ListSessions(ctx, domainReq)
	if err != nil {
		return nil, err
	}

	grpcResp := &gen.ListSessionsResponse{}
	
	for _, session := range resp.Sessions {
		grpcResp.Sessions = append(grpcResp.Sessions, &gen.SessionInfo{
			ContainerPath:  session.ContainerPath,
			CreatedAt:      session.CreatedAt.Unix(),
			ExpiresAt:      session.ExpiresAt.Unix(),
			LastAccessAt:   session.LastAccessAt.Unix(),
		})
	}

	if resp.Error != nil {
		grpcResp.Error = &gen.AgentError{Message: resp.Error.Message}
	}

	return grpcResp, nil
}
