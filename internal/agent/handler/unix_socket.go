package handler

import (
	"context"
	"encoding/json"
	"net"
)

type Command string

const (
	CmdCreateSession  Command = "create_session"
	CmdGetFEK         Command = "get_fek"
	CmdRefreshSession Command = "refresh_session"
	CmdCloseSession   Command = "close_session"
	CmdListSessions   Command = "list_sessions"
)

// Unix Socket транспорт
type UnixSocketTransport struct {
	handler    Handler
	socketPath string
	listener   net.Listener
}

func NewUnixSocketTransport(handler Handler, socketPath string) *UnixSocketTransport {
	return &UnixSocketTransport{
		handler:    handler,
		socketPath: socketPath,
	}
}

func (ut *UnixSocketTransport) Start(ctx context.Context) error {
	var err error
	ut.listener, err = net.Listen("unix", ut.socketPath)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		ut.listener.Close()
	}()

	for {
		conn, err := ut.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}

		go ut.handleConnection(ctx, conn)
	}
}

func (ut *UnixSocketTransport) Stop() error {
	if ut.listener != nil {
		return ut.listener.Close()
	}
	return nil
}

// Unix Socket специфичные типы
type UnixMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func (ut *UnixSocketTransport) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var msg UnixMessage
	if err := decoder.Decode(&msg); err != nil {
		return
	}

	switch Command(msg.Type) {
	case CmdCreateSession:
		ut.handleCreateSession(ctx, msg.Data, encoder)
	case CmdGetFEK:
		ut.handleGetFEK(ctx, msg.Data, encoder)
	case CmdRefreshSession:
		ut.handleRefreshSession(ctx, msg.Data, encoder)
	case CmdCloseSession:
		ut.handleCloseSession(ctx, msg.Data, encoder)
	case CmdListSessions:
		ut.handleListSessions(ctx, msg.Data, encoder)
	default:
		encoder.Encode(map[string]string{"error": "unknown command"})
	}
}

func (ut *UnixSocketTransport) handleCreateSession(ctx context.Context, data json.RawMessage, encoder *json.Encoder) {
	var unixReq CreateSessionRequest
	if err := json.Unmarshal(data, &unixReq); err != nil {
		encoder.Encode(CreateSessionResponse{Success: false, Error: &AgentError{Message: "invalid request"}})
		return
	}

	domainReq := &CreateSessionRequest{
		Meta: Meta{
			ContainerPath: unixReq.Meta.ContainerPath,
			UserID:        unixReq.Meta.UserID,
			MAC:           unixReq.Meta.MAC,
		},
		Password:   unixReq.Password,
		TTLSeconds: unixReq.TTLSeconds,
	}

	resp, err := ut.handler.CreateSession(ctx, domainReq)
	if err != nil {
		encoder.Encode(CreateSessionResponse{Success: false, Error: &AgentError{Message: err.Error()}})
		return
	}

	unixResp := CreateSessionResponse{
		Success:   resp.Success,
		ExpiresAt: resp.ExpiresAt,
	}
	if resp.Error != nil {
		unixResp.Error.Message = resp.Error.Message
	}

	encoder.Encode(unixResp)
}

func (ut *UnixSocketTransport) handleGetFEK(ctx context.Context, data json.RawMessage, encoder *json.Encoder) {
	var unixReq GetFEKRequest
	if err := json.Unmarshal(data, &unixReq); err != nil {
		encoder.Encode(GetFEKResponse{Success: false, Error: &AgentError{Message: "invalid request"}})
		return
	}

	domainReq := &GetFEKRequest{
		Meta: Meta{
			ContainerPath: unixReq.Meta.ContainerPath,
			UserID:        unixReq.Meta.UserID,
			MAC:           unixReq.Meta.MAC,
		},
	}

	resp, err := ut.handler.GetFEK(ctx, domainReq)
	if err != nil {
		encoder.Encode(GetFEKResponse{Success: false, Error: &AgentError{Message: "invalid request"}})
		return
	}

	unixResp := GetFEKResponse{
		Success: resp.Success,
		FEK:     resp.FEK,
		Found:   resp.Found,
	}
	if resp.Error != nil {
		unixResp.Error.Message = resp.Error.Message
	}

	encoder.Encode(unixResp)
}

func (ut *UnixSocketTransport) handleRefreshSession(ctx context.Context, data json.RawMessage, encoder *json.Encoder) {
	// Заглушка
}

func (ut *UnixSocketTransport) handleCloseSession(ctx context.Context, data json.RawMessage, encoder *json.Encoder) {
	// Заглушка
}

func (ut *UnixSocketTransport) handleListSessions(ctx context.Context, data json.RawMessage, encoder *json.Encoder) {
	// Заглушка
}

func stringPtr(s string) *string {
	return &s
}
