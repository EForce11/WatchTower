package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/EForce11/WatchTower/internal/config"
	pb "github.com/EForce11/WatchTower/pkg/protocol"
)

func sendHeartbeat(client pb.AgentServiceClient, agentID string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	now := time.Now()
	req := &pb.HeartbeatRequest{
		AgentId: agentID,
		Timestamp: &timestamp.Timestamp{
			Seconds: now.Unix(),
			Nanos:   int32(now.Nanosecond()), // #nosec G115 -- Nanosecond() ∈ [0,999_999_999], always within int32 range
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
	// Parse --config flag (optional).
	configPath := flag.String("config", "configs/sentry.yaml", "Path to YAML configuration file")
	flag.Parse()

	// Load configuration; fall back to built-in defaults when the file is absent.
	cfg, err := config.LoadSentryConfig(*configPath)
	if err != nil {
		log.Printf("WARNING: could not load config from %s: %v — using defaults", *configPath, err)
		cfg = config.DefaultSentryConfig()
	}

	// Allow the WT_HEARTBEAT_INTERVAL env var to override the config value.
	// This preserves backward compatibility with the integration test harness.
	heartbeatInterval := cfg.Heartbeat.Interval()
	if v := os.Getenv("WT_HEARTBEAT_INTERVAL"); v != "" {
		if d, parseErr := time.ParseDuration(v); parseErr == nil {
			heartbeatInterval = d
			log.Printf("Heartbeat interval overridden by WT_HEARTBEAT_INTERVAL: %v", d)
		}
	}

	// Attempt to connect to Core with retry logic
	var conn *grpc.ClientConn
	var connErr error

	maxRetries := cfg.Core.MaxRetries
	for attempt := 1; attempt <= maxRetries; attempt++ {
		log.Printf("Connecting to Core at %s (attempt %d/%d)", cfg.Core.Address, attempt, maxRetries)

		conn, connErr = grpc.NewClient(cfg.Core.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if connErr == nil {
			log.Printf("Connected to Core at %s", cfg.Core.Address)
			break
		}

		if attempt < maxRetries {
			backoff := time.Duration(1<<(attempt-1)) * time.Second
			time.Sleep(backoff)
		}
	}

	if connErr != nil {
		log.Printf("Failed to connect after %d attempts: %v", maxRetries, connErr)
		os.Exit(1)
	}

	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)

	// Create a cancelable context for the heartbeat loop
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
	sendHeartbeat(client, cfg.Agent.ID, cfg.Heartbeat.Timeout())

	// Then send at the configured interval
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sendHeartbeat(client, cfg.Agent.ID, cfg.Heartbeat.Timeout())
		case <-ctx.Done():
			return
		}
	}
}
