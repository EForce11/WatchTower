package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/EForce11/WatchTower/internal/config"
	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

type server struct {
	synapsev1.UnimplementedAgentServiceServer
}

func (s *server) Heartbeat(ctx context.Context, req *synapsev1.HeartbeatRequest) (*synapsev1.HeartbeatResponse, error) {
	if req.AgentId == "" {
		return nil, fmt.Errorf("agent_id required")
	}
	if req.Timestamp == nil {
		return nil, fmt.Errorf("timestamp required")
	}

	log.Printf("Heartbeat from agent_id=%s, timestamp=%d version=%s tier=%s",
		req.AgentId, req.Timestamp.Seconds, req.AgentVersion, req.CollectorTier)

	resp := &synapsev1.HeartbeatResponse{
		Status:     synapsev1.AgentStatus_AGENT_STATUS_OK,
		ServerTime: timestamppb.Now(),
	}
	return resp, nil
}

func main() {
	// Parse --config flag (optional).
	configPath := flag.String("config", "configs/core.yaml", "Path to YAML configuration file")
	flag.Parse()

	// Load configuration; fall back to built-in defaults when the file is absent.
	cfg, err := config.LoadCoreConfig(*configPath)
	if err != nil {
		log.Printf("WARNING: could not load config from %s: %v — using defaults", *configPath, err)
		cfg = config.DefaultCoreConfig()
	}

	// 1. Create TCP listener
	lis, err := net.Listen("tcp", cfg.Server.ListenAddress) // #nosec G102 -- intentional: gRPC server must accept connections from all interfaces
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// 2. Create gRPC server
	grpcServer := grpc.NewServer()

	// 3. Register AgentService
	synapsev1.RegisterAgentServiceServer(grpcServer, &server{})

	log.Printf("Starting WatchTower Core on %s", cfg.Server.ListenAddress)

	// 4. Start server in goroutine
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// 5. Setup signal handler for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// 6. Wait for shutdown signal
	<-quit

	// 7. Graceful stop
	log.Println("Shutting down gracefully...")
	grpcServer.GracefulStop()
}
