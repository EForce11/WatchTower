package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/EForce11/WatchTower/pkg/protocol"
)

const (
	coreAddress = "localhost:50051"
	agentID     = "sentry-test-001"
)

func sendHeartbeat(client pb.AgentServiceClient, agentID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	req := &pb.HeartbeatRequest{
		AgentId:   agentID,
		Timestamp: timestamppb.New(now),
	}

	resp, err := client.Heartbeat(ctx, req)
	if err != nil {
		log.Printf("Heartbeat failed: %v", err)
		return
	}

	log.Printf("Heartbeat sent: agent_id=%s, status=%s", agentID, resp.Status)
}

func main() {
	// Create a gRPC client connection (lazy — actual dial happens on first RPC).
	log.Printf("Connecting to Core at %s", coreAddress)
	conn, err := grpc.NewClient(coreAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)

	// Create a cancellable context for the heartbeat loop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("Shutting down...")
		cancel()
	}()

	// Send initial heartbeat immediately
	sendHeartbeat(client, agentID)

	// Then send on the configured interval (default 10 s, overridable via WT_HEARTBEAT_INTERVAL).
	interval := 10 * time.Second
	if v := os.Getenv("WT_HEARTBEAT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			interval = d
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sendHeartbeat(client, agentID)
		case <-ctx.Done():
			return
		}
	}
}
