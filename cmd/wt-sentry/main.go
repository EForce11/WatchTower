package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

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
		AgentId: agentID,
		Timestamp: &timestamp.Timestamp{
			Seconds: now.Unix(),
			Nanos:   int32(now.Nanosecond()),
		},
	}

	resp, err := client.Heartbeat(ctx, req)
	if err != nil {
		log.Printf("Heartbeat failed: %v", err)
		return
	}

	log.Printf("Heartbeat sent: agent_id=%s, status=%s", agentID, resp.Status)
}

func main() {
	// Attempt to connect to Core with retry logic
	var conn *grpc.ClientConn
	var connErr error

	for attempt := 1; attempt <= 3; attempt++ {
		log.Printf("Connecting to Core at %s (attempt %d/3)", coreAddress, attempt)

		conn, connErr = grpc.Dial(coreAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if connErr == nil {
			log.Printf("Connected to Core at %s", coreAddress)
			break
		}

		if attempt < 3 {
			backoff := time.Duration(1<<(attempt-1)) * time.Second
			time.Sleep(backoff)
		}
	}

	if connErr != nil {
		log.Printf("Failed to connect after 3 attempts: %v", connErr)
		os.Exit(1)
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

	// Then send every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
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
