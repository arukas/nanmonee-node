package control

import (
	"context"
	"crypto/subtle"
	"errors"
	"sort"
	"strings"

	nodev1 "nanmonee/node/api/node/v1"
	"nanmonee/node/internal/panel"
	noderuntime "nanmonee/node/internal/runtime"
	"nanmonee/node/internal/worker"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const maxRPCBytes = 1 << 20

type nodeControlServer struct {
	nodev1.UnimplementedNodeControlServer
	runtime *noderuntime.Runtime
	// observer is nil for a self-managed node that accepts external snapshots.
	observer worker.Observer
}

// NewServer builds the loopback control plane. Pass an observer for a
// panel-owned node so status can report the worker's own view.
func NewServer(runtime *noderuntime.Runtime, secret string, observer worker.Observer) *grpc.Server {
	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRPCBytes),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			values, _ := metadata.FromIncomingContext(ctx)
			authorization := values.Get("authorization")
			if len(authorization) != 1 || !strings.HasPrefix(authorization[0], "Bearer ") || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(authorization[0], "Bearer ")), []byte(secret)) != 1 {
				return nil, status.Error(codes.Unauthenticated, "valid bearer credentials are required")
			}
			return handler(ctx, req)
		}),
	)
	nodev1.RegisterNodeControlServer(server, &nodeControlServer{runtime: runtime, observer: observer})
	return server
}

func (s *nodeControlServer) GetStatus(context.Context, *nodev1.GetStatusRequest) (*nodev1.GetStatusResponse, error) {
	return &nodev1.GetStatusResponse{Status: s.status()}, nil
}

func (s *nodeControlServer) status() *nodev1.Status {
	current := convertStatus(s.runtime.Status())
	if s.observer == nil {
		return current
	}
	observed := s.observer.Observation()
	current.Panel = &nodev1.PanelObservation{
		Host:           observed.PanelHost,
		LastPullUnix:   observed.LastPullAt.Unix(),
		LastPushUnix:   observed.LastPushAt.Unix(),
		Rejected:       observed.Rejected,
		PendingBatches: int32(observed.PendingBatches),
		PendingMembers: int32(observed.PendingMembers),
		LastError:      observed.LastError,
	}
	if current.LastError == "" && observed.LastError != "" {
		current.LastError = observed.LastError
	}
	return current
}

func (s *nodeControlServer) ApplySnapshot(ctx context.Context, request *nodev1.ApplySnapshotRequest) (*nodev1.ApplySnapshotResponse, error) {
	var config *noderuntime.Config
	if request.Config != nil {
		switch {
		case request.Config.GetVless() != nil:
			vless := request.Config.GetVless()
			converted := noderuntime.VlessRuntimeConfig(noderuntime.VlessConfig{
				Listen:            vless.Listen,
				Port:              vless.Port,
				ServerName:        vless.ServerName,
				HandshakeServer:   vless.HandshakeServer,
				HandshakePort:     vless.HandshakePort,
				RealityPrivateKey: vless.RealityPrivateKey,
				RealityShortID:    vless.RealityShortId,
			})
			config = &converted
		case request.Config.GetHysteria2() != nil:
			hysteria2 := request.Config.GetHysteria2()
			converted := noderuntime.Hysteria2RuntimeConfig(noderuntime.Hysteria2Config{
				Listen:          hysteria2.Listen,
				Port:            hysteria2.Port,
				ServerName:      hysteria2.ServerName,
				CertificatePath: hysteria2.CertificatePath,
				PrivateKeyPath:  hysteria2.PrivateKeyPath,
			})
			config = &converted
		default:
			// NodeConfig carries only VLESS and Hysteria2 today. A client that
			// sends a future protocol must not be answered with a silent "no new
			// config": Apply would report success while the listener never moves.
			return &nodev1.ApplySnapshotResponse{Status: s.status()}, status.Error(codes.InvalidArgument, "unsupported node config protocol")
		}
	}
	var users *[]noderuntime.User
	if request.Users != nil {
		converted := make([]noderuntime.User, 0, len(request.Users.Users))
		for _, user := range request.Users.Users {
			converted = append(converted, noderuntime.User{MemberID: user.MemberId, UUID: user.Uuid})
		}
		users = &converted
	}
	_, err := s.runtime.Apply(ctx, noderuntime.ApplyInput{
		ExpectedRuntimeID:     request.ExpectedRuntimeId,
		ExpectedStateRevision: request.ExpectedStateRevision,
		Config:                config,
		Users:                 users,
	})
	if err != nil {
		return &nodev1.ApplySnapshotResponse{Status: s.status()}, grpcError(err)
	}
	return &nodev1.ApplySnapshotResponse{Status: s.status()}, nil
}

func (s *nodeControlServer) GetUsageSnapshot(context.Context, *nodev1.GetUsageSnapshotRequest) (*nodev1.GetUsageSnapshotResponse, error) {
	usage, err := s.runtime.Usage()
	if err != nil {
		return nil, status.Error(codes.Internal, "usage snapshot is unavailable")
	}
	memberIDs := make([]int64, 0, len(usage.Members))
	for memberID := range usage.Members {
		memberIDs = append(memberIDs, memberID)
	}
	sort.Slice(memberIDs, func(i, j int) bool { return memberIDs[i] < memberIDs[j] })
	response := &nodev1.GetUsageSnapshotResponse{RuntimeId: usage.RuntimeID, Usage: make([]*nodev1.MemberUsage, 0, len(memberIDs))}
	for _, memberID := range memberIDs {
		counters := usage.Members[memberID]
		response.Usage = append(response.Usage, &nodev1.MemberUsage{MemberId: memberID, Upload: counters[0], Download: counters[1]})
	}
	return response, nil
}

func convertStatus(current noderuntime.Status) *nodev1.Status {
	state := nodev1.RuntimeState_RUNTIME_STATE_UNSPECIFIED
	switch current.State {
	case noderuntime.StateEmpty:
		state = nodev1.RuntimeState_RUNTIME_STATE_EMPTY
	case noderuntime.StateRunning:
		state = nodev1.RuntimeState_RUNTIME_STATE_RUNNING
	case noderuntime.StateDegraded:
		state = nodev1.RuntimeState_RUNTIME_STATE_DEGRADED
	}
	return &nodev1.Status{
		AgentVersion:        panel.AgentVersion,
		ApiVersion:          panel.BackendProtocol,
		CoreVersion:         panel.KernelVersion,
		CoreCommit:          panel.KernelCommit,
		SupportedProtocols:  []string{current.Protocol},
		Protocol:            current.Protocol,
		State:               state,
		RuntimeId:           current.RuntimeID,
		StateRevision:       current.StateRevision,
		ConfigSha256:        current.ConfigSHA256,
		AuthorizationSha256: current.AuthorizationSHA256,
		LastError:           current.LastError,
		PanelOwned:          current.PanelOwned,
		Configured:          current.Configured,
	}
}

func grpcError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "apply canceled; read status to reconcile the write")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "apply deadline exceeded; read status to reconcile the write")
	case errors.Is(err, noderuntime.ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, noderuntime.ErrConflict):
		return status.Error(codes.Aborted, "snapshot conflicts with current runtime state")
	case errors.Is(err, noderuntime.ErrFailedPrecondition):
		return status.Error(codes.FailedPrecondition, "runtime does not accept snapshots")
	case errors.Is(err, noderuntime.ErrResourceExhausted):
		return status.Error(codes.ResourceExhausted, "snapshot exceeds the member limit")
	default:
		return status.Error(codes.Internal, "runtime apply failed; read status for the actual state")
	}
}
