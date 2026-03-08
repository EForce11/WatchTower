package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	pb "github.com/EForce11/WatchTower/pkg/protocol"
)

const port = ":50051"

type server struct {
	pb.UnimplementedAgentServiceServer
}

func (s *server) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if req.AgentId == "" {
		return nil, fmt.Errorf("agent_id required")
	}
	if req.Timestamp == nil {
		return nil, fmt.Errorf("timestamp required")
	}

	log.Printf("Heartbeat from agent_id=%s, timestamp=%d", req.AgentId, req.Timestamp.Seconds)

	resp := &pb.HeartbeatResponse{
		Status: pb.AgentStatus_AGENT_STATUS_OK,
	}
	return resp, nil
}

func main() {
	// 1. Create TCP listener on :50051
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// 2. Create gRPC server
	grpcServer := grpc.NewServer()

	// 3. Register AgentService
	pb.RegisterAgentServiceServer(grpcServer, &server{})

	log.Println("Starting WatchTower Core on :50051")

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
