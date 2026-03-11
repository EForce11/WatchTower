# WatchTower XDR - Agent Handoff Guide

**Purpose:** Copy-paste prompts for AI agents (Antigravity)  
**Strategy:** Fresh chat per task → context isolation → quality control  
**Quality:** Code Agent → Test Agent → Security Agent

---

## 📋 How to Use This Guide

### Workflow for Each Task

```
1. Open Antigravity IDE
2. Start NEW chat (fresh context)
3. Find task in this file (e.g., "Task 0.4")
4. Copy ENTIRE prompt
5. Paste into chat
6. Review generated code
7. Run verification commands
8. If ✅ pass → commit + update progress.md
9. If ❌ fail → iterate with agent or try different agent
```

### Agent Roles

- **Code Agent:** Writes implementation code
- **Test Agent:** Writes tests, verifies quality
- **Security Agent:** Reviews for vulnerabilities

**Rule:** Never use same agent for code + security review (conflict of interest)

---

## 🎯 Phase 0: Preparation

### Task 0.4 - Protobuf Compilation ⚡ COMPLETED

**Agent Role:** Code Agent  
**Chat Type:** New chat (fresh start)  
**Prerequisites:** `pkg/protocol/agent.proto` exists

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 0.4 - Compile Protobuf to Go

## Context
Project: WatchTower XDR (self-hosted security platform)
Language: Go 1.21+
Phase: 0.4 - Compile protocol definition to Go code
Previous work: agent.proto file already exists

## Current State
File exists: pkg/protocol/agent.proto ✅
Content includes:
- HeartbeatRequest message
- HeartbeatResponse message  
- AgentService with Heartbeat RPC

**IMPORTANT:** go.mod does NOT exist yet - must create first!

## Task
1. Initialize Go module
2. Install protobuf plugins
3. Generate Go code from protobuf

## Step-by-Step Requirements

### Step 1: Initialize Go Module (REQUIRED FIRST)
```bash
# Navigate to project root
cd /path/to/WatchTower

# Initialize Go module
go mod init github.com/EForce11/WatchTower

# Verify
cat go.mod
# Should show:
# module github.com/EForce11/WatchTower
# go 1.21 (or higher)
```

### Step 2: Verify Prerequisites
```bash
go version  # Should be 1.21+
which protoc  # Should exist
```

### Step 3: Install Protobuf Plugins
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
export PATH="$PATH:$(go env GOPATH)/bin"

# Verify plugins installed
which protoc-gen-go
which protoc-gen-go-grpc
```

### Step 4: Compile Protobuf
```bash
protoc --go_out=. --go-grpc_out=. pkg/protocol/agent.proto
```

### Step 5: Update Dependencies
```bash
go mod tidy
```

## Expected Output Files
After completion, these files should exist:
- go.mod ✅
- go.sum ✅
- pkg/protocol/agent.pb.go ✅
- pkg/protocol/agent_grpc.pb.go ✅

## Success Criteria

Run ALL these commands - all must succeed:
```bash
# 1. Go module initialized
cat go.mod | grep "module github.com/EForce11/WatchTower"

# 2. Generated files exist
ls pkg/protocol/agent.pb.go
ls pkg/protocol/agent_grpc.pb.go

# 3. No syntax errors
go build ./pkg/protocol/

# 4. Dependencies updated
cat go.mod | grep google.golang.org/grpc
cat go.mod | grep google.golang.org/protobuf

# 5. go.sum created
ls go.sum
```

## Deliverable
Provide:
1. Exact commands you ran (in order)
2. Output of each command
3. Final contents of go.mod
4. Confirmation all 5 success criteria pass

## After Completion
1. Verify all success criteria ✅
2. Commit:
   ```bash
   git add go.mod go.sum pkg/protocol/*.pb.go
   git commit -m "feat: initialize go module and compile protobuf (Phase 0.4)"
   git push
   ```
3. Update progress.md: Mark task 0.4 as ✅
4. Proceed to task 0.5

## Next Task
Task 0.5 - Core server skeleton (cmd/wt-core/main.go)
```

**✅ After Agent Completes:**
```bash
# 1. Verify yourself
ls pkg/protocol/*.pb.go
go build ./pkg/protocol/

# 2. Commit
git add go.mod go.sum pkg/protocol/*.pb.go
git commit -m "feat: compile protobuf to Go (Phase 0.4)"
git push

# 3. Update progress.md
# Mark task 0.4 as ✅ complete

# 4. Move to task 0.5
```

---

### Task 0.5 - Core Server Skeleton

**Agent Role:** Code Agent  
**Prerequisites:** Task 0.4 complete (protobuf compiled)

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 0.5 - Core gRPC Server Skeleton

## Context
Project: WatchTower XDR
Component: WT-Core (central server)
Phase: 0.5 - Create basic gRPC server
Previous: Protobuf compiled successfully (agent.pb.go exists)

## Task
Create cmd/wt-core/main.go that starts a gRPC server on port 50051.

## Requirements

1. **File to Create:** cmd/wt-core/main.go

2. **Implementation Must Include:**
   - Import generated protobuf code from pkg/protocol
   - Create gRPC server listening on port 50051
   - Embed UnimplementedAgentServiceServer (required by gRPC)
   - Log "Starting WatchTower Core on :50051" on startup
   - Handle graceful shutdown (SIGINT, SIGTERM signals)
   - No errors, no warnings

3. **Required Imports:**
   ```go
   import (
       "context"
       "log"
       "net"
       "os"
       "os/signal"
       "syscall"
       
       "google.golang.org/grpc"
       pb "github.com/EForce11/WatchTower/pkg/protocol"
   )
   ```

4. **Code Structure:**
   ```go
   package main

   // Imports...

   type server struct {
       pb.UnimplementedAgentServiceServer
   }

   func main() {
       // 1. Create TCP listener on :50051
       // 2. Create gRPC server
       // 3. Register AgentService
       // 4. Start server in goroutine
       // 5. Setup signal handler for graceful shutdown
       // 6. Wait for shutdown signal
       // 7. Call GracefulStop()
   }
   ```

5. **Logging Requirements:**
   - On startup: `log.Println("Starting WatchTower Core on :50051")`
   - On shutdown: `log.Println("Shutting down gracefully...")`
   - On errors: `log.Fatalf("Error: %v", err)`

## Success Criteria

Test with these commands:
```bash
# 1. Build succeeds (no errors)
go build -o wt-core cmd/wt-core/main.go
echo "Exit code: $?"  # Should be 0

# 2. Run server
./wt-core
# Expected output:
# 2026/02/08 15:00:00 Starting WatchTower Core on :50051
# (server stays running)

# 3. Verify port listening (in another terminal)
netstat -tuln | grep 50051
# Should show:
# tcp ... 0.0.0.0:50051 ... LISTEN

# 4. Graceful shutdown works
# Press Ctrl+C in server terminal
# Expected output:
# 2026/02/08 15:00:10 Shutting down gracefully...
# (server exits cleanly)

# 5. No errors in any step
```

## Deliverables
1. Complete cmd/wt-core/main.go file
2. Confirmation that all success criteria pass

## Quality Checklist
- [ ] Imports use correct GitHub path (github.com/EForce11/WatchTower)
- [ ] Error handling for listener.Listen()
- [ ] Graceful shutdown channel created
- [ ] No hard-coded magic numbers (use const PORT = "50051")
- [ ] Log messages are clear
- [ ] Code follows Go conventions (gofmt compatible)

## Next Task
Task 0.6 - Implement Heartbeat RPC method in this file
```

---

### Task 0.6 - Heartbeat RPC Implementation

**Agent Role:** Code Agent  
**Prerequisites:** Task 0.5 complete (server starts successfully)

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 0.6 - Heartbeat RPC Implementation

## Context
Project: WatchTower XDR
Component: WT-Core
Phase: 0.6 - Implement Heartbeat RPC method
Current State: Server runs and listens on :50051, but Heartbeat RPC not implemented

## Task
Update cmd/wt-core/main.go to implement the Heartbeat RPC method.

## Requirements

1. **Add Heartbeat Method to Server Struct:**
   ```go
   func (s *server) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
       // Implementation here
   }
   ```

2. **Implementation Logic:**
   - Extract agent_id and timestamp from request
   - Validate inputs (see error handling below)
   - Log the heartbeat with format: `"Heartbeat from agent_id=%s, timestamp=%d"`
   - Create response with:
     - status: "OK"
     - server_time: current Unix timestamp
   - Return response

3. **Error Handling:**
   ```go
   if req.AgentId == "" {
       return nil, fmt.Errorf("agent_id required")
   }
   if req.Timestamp == 0 {
       return nil, fmt.Errorf("timestamp required")
   }
   ```

4. **Response Creation:**
   ```go
   resp := &pb.HeartbeatResponse{
       Status:     "OK",
       ServerTime: time.Now().Unix(),
   }
   return resp, nil
   ```

## Success Criteria

```bash
# 1. Server starts (no changes to startup)
go run cmd/wt-core/main.go
# Logs: "Starting WatchTower Core on :50051"

# 2. Test with grpcurl (install if needed: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest)
# In another terminal:
grpcurl -plaintext -d '{"agent_id":"test-agent-1","timestamp":1707408000}' \
  localhost:50051 protocol.AgentService/Heartbeat

# Expected response:
# {
#   "status": "OK",
#   "serverTime": 1707408900
# }

# Expected log in server terminal:
# 2026/02/08 15:15:00 Heartbeat from agent_id=test-agent-1, timestamp=1707408000

# 3. Test error cases
grpcurl -plaintext -d '{"timestamp":123}' \
  localhost:50051 protocol.AgentService/Heartbeat
# Expected: ERROR ... agent_id required

grpcurl -plaintext -d '{"agent_id":"test"}' \
  localhost:50051 protocol.AgentService/Heartbeat
# Expected: ERROR ... timestamp required

# 4. Stress test (5 rapid heartbeats)
for i in {1..5}; do
  grpcurl -plaintext -d "{\"agent_id\":\"test-$i\",\"timestamp\":$((1707408000+i))}" \
    localhost:50051 protocol.AgentService/Heartbeat
done
# Should see 5 log entries, no crashes, all return OK
```

## Deliverable
Updated cmd/wt-core/main.go with working Heartbeat implementation.

## grpcurl Installation Note
If grpcurl not installed:
```bash
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Next Task
Task 0.7 - Sentry client skeleton (connects to this Core)
```

---

### Task 0.7 - Sentry Client Skeleton

**Agent Role:** Code Agent  
**Prerequisites:** Task 0.6 complete (Core accepts and responds to Heartbeat)

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 0.7 - Sentry gRPC Client Skeleton

## Context
Project: WatchTower XDR
Component: WT-Sentry (monitoring agent)
Phase: 0.7 - Create gRPC client that connects to Core
Core Status: Running on localhost:50051, Heartbeat RPC fully functional

## Task
Create cmd/wt-sentry/main.go that connects to Core via gRPC.

## Requirements

1. **File to Create:** cmd/wt-sentry/main.go

2. **Constants:**
   ```go
   const (
       coreAddress = "localhost:50051"
       agentID     = "sentry-test-001"
   )
   ```

3. **Implementation:**
   - Connect to Core using gRPC
   - Use insecure connection (mTLS comes later in Phase 2)
   - Implement retry logic: 3 attempts with exponential backoff (1s, 2s, 4s)
   - Log each connection attempt
   - Log successful connection
   - Handle graceful shutdown (SIGINT, SIGTERM)
   - Close connection on shutdown

4. **Retry Logic:**
   ```go
   for attempt := 1; attempt <= 3; attempt++ {
       log.Printf("Connecting to Core at %s (attempt %d/3)", coreAddress, attempt)
       
       conn, err := grpc.Dial(coreAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
       if err == nil {
           log.Printf("Connected to Core at %s", coreAddress)
           break
       }
       
       if attempt < 3 {
           backoff := time.Duration(1<<(attempt-1)) * time.Second
           time.Sleep(backoff)
       }
   }
   ```

5. **Logging:**
   - Connection attempt: `"Connecting to Core at localhost:50051 (attempt X/3)"`
   - Success: `"Connected to Core at localhost:50051"`
   - Failure: `"Failed to connect after 3 attempts: [error]"`
   - Shutdown: `"Shutting down..."`

## Success Criteria

```bash
# Test 1: Successful connection
# Terminal 1: Start Core
go run cmd/wt-core/main.go
# Logs: "Starting WatchTower Core on :50051"

# Terminal 2: Start Sentry
go run cmd/wt-sentry/main.go
# Expected output:
# 2026/02/08 15:30:00 Connecting to Core at localhost:50051 (attempt 1/3)
# 2026/02/08 15:30:00 Connected to Core at localhost:50051
# (stays running, doesn't exit)

# Test 2: Connection failure (retry logic)
# Stop Core (Ctrl+C in terminal 1)
# Start Sentry again in terminal 2
# Expected output:
# 2026/02/08 15:31:00 Connecting to Core at localhost:50051 (attempt 1/3)
# (wait 1 second)
# 2026/02/08 15:31:01 Connecting to Core at localhost:50051 (attempt 2/3)
# (wait 2 seconds)
# 2026/02/08 15:31:03 Connecting to Core at localhost:50051 (attempt 3/3)
# (wait 4 seconds)
# 2026/02/08 15:31:07 Failed to connect after 3 attempts: ...
# (exits)

# Test 3: Graceful shutdown
# With both Core and Sentry running, press Ctrl+C in Sentry terminal
# Expected: "Shutting down..." (no errors, clean exit)

# Test 4: No crashes for 2 minutes
# Let both run for 120 seconds
# No panics, no errors
```

## Deliverable
Complete cmd/wt-sentry/main.go with connection logic and retry mechanism.

## Required Imports
```go
import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"
    
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    pb "github.com/EForce11/WatchTower/pkg/protocol"
)
```

## Next Task
Task 0.8 - Send heartbeats every 10 seconds from Sentry to Core
```

---

### Task 0.8 - Heartbeat Sender

**Agent Role:** Code Agent  
**Prerequisites:** Task 0.7 complete (Sentry connects to Core)

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 0.8 - Heartbeat Sender

## Context
Project: WatchTower XDR
Component: WT-Sentry
Phase: 0.8 - Send periodic heartbeats to Core
Current State: Sentry connects to Core successfully, but doesn't send heartbeats yet

## Task
Update cmd/wt-sentry/main.go to send heartbeats every 10 seconds.

## Requirements

1. **Add Heartbeat Sending Logic:**
   After successful connection, implement periodic heartbeat sending

2. **Create sendHeartbeat() Function:**
   ```go
   func sendHeartbeat(client pb.AgentServiceClient, agentID string) {
       ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
       defer cancel()
       
       req := &pb.HeartbeatRequest{
           AgentId:   agentID,
           Timestamp: time.Now().Unix(),
       }
       
       resp, err := client.Heartbeat(ctx, req)
       if err != nil {
           log.Printf("Heartbeat failed: %v", err)
           return
       }
       
       log.Printf("Heartbeat sent: agent_id=%s, status=%s, server_time=%d", 
           agentID, resp.Status, resp.ServerTime)
   }
   ```

3. **Main Loop Update:**
   ```go
   // After successful connection:
   client := pb.NewAgentServiceClient(conn)
   
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
   ```

4. **Error Handling:**
   - Set timeout: 5 seconds per heartbeat
   - Log failures but DON'T crash (continue sending)
   - Retry on next tick

5. **Context Management:**
   - Create cancellable context
   - Cancel on shutdown signal
   - Graceful exit from loop

## Success Criteria

```bash
# Test: End-to-end heartbeat flow
# Terminal 1: Core
go run cmd/wt-core/main.go

# Terminal 2: Sentry
go run cmd/wt-sentry/main.go

# Sentry logs (should appear every 10 seconds):
# 2026/02/08 16:00:00 Connected to Core at localhost:50051
# 2026/02/08 16:00:00 Heartbeat sent: agent_id=sentry-test-001, status=OK, server_time=1707415200
# 2026/02/08 16:00:10 Heartbeat sent: agent_id=sentry-test-001, status=OK, server_time=1707415210
# 2026/02/08 16:00:20 Heartbeat sent: agent_id=sentry-test-001, status=OK, server_time=1707415220
# ...

# Core logs (matching heartbeats):
# 2026/02/08 16:00:00 Starting WatchTower Core on :50051
# 2026/02/08 16:00:00 Heartbeat from agent_id=sentry-test-001, timestamp=1707415200
# 2026/02/08 16:00:10 Heartbeat from agent_id=sentry-test-001, timestamp=1707415210
# 2026/02/08 16:00:20 Heartbeat from agent_id=sentry-test-001, timestamp=1707415220
# ...

# Test: Resilience (Core restarts)
# 1. Stop Core (Ctrl+C in terminal 1)
# 2. Wait 30 seconds (Sentry should log "Heartbeat failed")
# 3. Restart Core (go run cmd/wt-core/main.go)
# 4. Sentry should automatically resume sending heartbeats
# Expected: No crashes, reconnects seamlessly

# Test: Long duration
# Let both run for 2 minutes
# Expected: 12 heartbeats logged, no errors, no memory leaks
```

## Deliverable
Updated cmd/wt-sentry/main.go with periodic heartbeat sending.

## Quality Checklist
- [ ] Immediate heartbeat sent (not after 10 second wait)
- [ ] Ticker cleanup (defer ticker.Stop())
- [ ] Context cancellation handled
- [ ] Errors logged but don't crash
- [ ] Timeout set (5 seconds)

## Next Task
Task 0.9 - Automated integration test (Test Agent)
```

---

## 🎯 Phase 1: Watcher (Log Monitoring)

### Task 1.1 - fsnotify Log Watcher ⚡ NEXT TASK

**Agent Role:** Code Agent  
**Chat Type:** New chat (fresh start)  
**Prerequisites:** Phase 0 complete (v0.2.0 tagged)

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 1.1 - fsnotify Log Watcher

## Context
Project: WatchTower XDR
Component: WT-Sentry (monitoring agent)
Phase: 1.1 - Implement real-time log monitoring
Previous: Phase 0 complete (gRPC communication working)

## Task
Create internal/sentry/logwatcher.go that monitors log files for changes using fsnotify (inotify).

## Requirements

### 1. File to Create
`internal/sentry/logwatcher.go`

### 2. Implementation

```go
package sentry

import (
    "bufio"
    "context"
    "log"
    "os"
    "time"
    
    "github.com/fsnotify/fsnotify"
)

// LogWatcher monitors log files for new entries
type LogWatcher struct {
    watcher  *fsnotify.Watcher
    logPaths []string
    events   chan LogEvent
}

// LogEvent represents a new log line
type LogEvent struct {
    FilePath  string
    Line      string
    Timestamp int64
}

// NewLogWatcher creates a new log watcher
func NewLogWatcher(logPaths []string) (*LogWatcher, error) {
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return nil, err
    }
    
    // Add log files to watcher
    for _, path := range logPaths {
        if err := watcher.Add(path); err != nil {
            return nil, err
        }
    }
    
    return &LogWatcher{
        watcher:  watcher,
        logPaths: logPaths,
        events:   make(chan LogEvent, 100), // Buffered channel
    }, nil
}

// Watch starts monitoring log files
func (lw *LogWatcher) Watch(ctx context.Context) {
    go func() {
        for {
            select {
            case event := <-lw.watcher.Events:
                if event.Op&fsnotify.Write == fsnotify.Write {
                    lw.handleFileChange(event.Name)
                }
            case err := <-lw.watcher.Errors:
                log.Printf("Watcher error: %v", err)
            case <-ctx.Done():
                return
            }
        }
    }()
}

// handleFileChange reads new lines from modified file
func (lw *LogWatcher) handleFileChange(filePath string) {
    file, err := os.Open(filePath)
    if err != nil {
        log.Printf("Error opening file %s: %v", filePath, err)
        return
    }
    defer file.Close()
    
    // Seek to end of file (we only want new lines)
    file.Seek(0, os.SEEK_END)
    
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        lw.events <- LogEvent{
            FilePath:  filePath,
            Line:      scanner.Text(),
            Timestamp: time.Now().Unix(),
        }
    }
}

// Events returns channel for receiving log events
func (lw *LogWatcher) Events() <-chan LogEvent {
    return lw.events
}

// Close stops the watcher
func (lw *LogWatcher) Close() error {
    close(lw.events)
    return lw.watcher.Close()
}
```

### 3. Unit Test

Create `internal/sentry/logwatcher_test.go`:

```go
package sentry

import (
    "context"
    "os"
    "testing"
    "time"
)

func TestLogWatcher_DetectsNewLines(t *testing.T) {
    // Create temp log file
    tmpfile, err := os.CreateTemp("", "test.log")
    if err != nil {
        t.Fatal(err)
    }
    defer os.Remove(tmpfile.Name())
    
    // Create watcher
    watcher, err := NewLogWatcher([]string{tmpfile.Name()})
    if err != nil {
        t.Fatal(err)
    }
    defer watcher.Close()
    
    // Start watching
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    watcher.Watch(ctx)
    
    // Write to log file
    testLine := "Test log entry"
    tmpfile.WriteString(testLine + "\n")
    tmpfile.Sync()
    
    // Verify event received
    select {
    case event := <-watcher.Events():
        if event.Line != testLine {
            t.Errorf("Expected %q, got %q", testLine, event.Line)
        }
    case <-time.After(2 * time.Second):
        t.Error("Timeout waiting for log event")
    }
}
```

## Success Criteria

```bash
# 1. Install fsnotify dependency
go get github.com/fsnotify/fsnotify
go mod tidy

# 2. Code compiles
go build ./internal/sentry/

# 3. Unit tests pass
go test -v ./internal/sentry/
# Expected: PASS

# 4. Manual test
# Create test log:
echo "test 1" >> /tmp/test.log

# Run watcher (in go):
watcher := NewLogWatcher([]string{"/tmp/test.log"})
watcher.Watch(ctx)

# In another terminal:
echo "test 2" >> /tmp/test.log

# Should see event immediately (<100ms)
```

## Deliverables
1. `internal/sentry/logwatcher.go` (complete implementation)
2. `internal/sentry/logwatcher_test.go` (unit tests)
3. Confirmation both compile and tests pass

## Notes
- Use fsnotify for cross-platform compatibility (Linux, macOS)
- Buffer channel (100 events) prevents blocking
- Context-aware for graceful shutdown
- Only emit new lines (seek to end of file)

## Next Task
Task 1.2 - Regex pattern matcher (uses LogEvent output)
```

**After Completion:**
```bash
# 1. Install dependency
go get github.com/fsnotify/fsnotify
go mod tidy

# 2. Verify
go test ./internal/sentry/

# 3. Commit
git add internal/sentry/logwatcher*.go go.mod go.sum
git commit -m "feat(sentry): implement fsnotify log watcher (Phase 1.1)"
git push

# 4. Update progress.md (mark 1.1 as ✅)
# 5. Move to task 1.2
```

---

### Task 1.2 - Regex Pattern Matcher

**Agent Role:** Code Agent  
**Prerequisites:** Task 1.1 complete (LogWatcher working)

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 1.2 - Regex Pattern Matcher

## Context
Project: WatchTower XDR
Component: WT-Sentry
Phase: 1.2 - Pattern matching for security events
Previous: Task 1.1 complete (LogWatcher emits LogEvents)

## Task
Create internal/sentry/patterns.go that matches log lines against security patterns.

## Requirements

### Pattern Categories
1. **SSH Brute Force:** Failed password attempts
2. **SQL Injection:** SQLi attack patterns in web logs
3. **XSS Attempts:** Cross-site scripting patterns
4. **Path Traversal:** Directory traversal attempts
5. **Port Scanning:** Sequential connection attempts

### Implementation

```go
package sentry

import (
    "regexp"
)

// Pattern represents a security detection pattern
type Pattern struct {
    Name        string
    Regex       *regexp.Regexp
    Severity    int  // 1-4 (1=low, 4=critical)
    Description string
}

// PatternMatcher holds all detection patterns
type PatternMatcher struct {
    patterns []Pattern
}

// NewPatternMatcher creates matcher with default patterns
func NewPatternMatcher() *PatternMatcher {
    return &PatternMatcher{
        patterns: []Pattern{
            // SSH patterns
            {
                Name:        "SSH_FAILED_PASSWORD",
                Regex:       regexp.MustCompile(`Failed password for .* from ([\d\.]+)`),
                Severity:    2,
                Description: "SSH failed login attempt",
            },
            {
                Name:        "SSH_INVALID_USER",
                Regex:       regexp.MustCompile(`Invalid user .* from ([\d\.]+)`),
                Severity:    2,
                Description: "SSH login attempt with invalid user",
            },
            
            // SQL Injection patterns
            {
                Name:        "SQLI_UNION",
                Regex:       regexp.MustCompile(`(?i)(union.*select|select.*from)`),
                Severity:    4,
                Description: "SQL injection attempt (UNION/SELECT)",
            },
            {
                Name:        "SQLI_COMMENT",
                Regex:       regexp.MustCompile(`(--|#|\/\*|\*\/)`),
                Severity:    3,
                Description: "SQL injection attempt (comment syntax)",
            },
            
            // XSS patterns
            {
                Name:        "XSS_SCRIPT_TAG",
                Regex:       regexp.MustCompile(`(?i)<script[^>]*>.*</script>`),
                Severity:    4,
                Description: "XSS attempt (script tag)",
            },
            {
                Name:        "XSS_EVENT_HANDLER",
                Regex:       regexp.MustCompile(`(?i)on(load|error|click|mouseover)=`),
                Severity:    3,
                Description: "XSS attempt (event handler)",
            },
            
            // Path Traversal
            {
                Name:        "PATH_TRAVERSAL",
                Regex:       regexp.MustCompile(`\.\./|\.\.\\`),
                Severity:    3,
                Description: "Directory traversal attempt",
            },
            
            // Port Scanning
            {
                Name:        "PORT_SCAN",
                Regex:       regexp.MustCompile(`SYN.*sport=(\d+).*dport=(\d+)`),
                Severity:    2,
                Description: "Potential port scanning activity",
            },
            
            // Command Injection
            {
                Name:        "COMMAND_INJECTION",
                Regex:       regexp.MustCompile(`(;|\||&|`+"`"+`).*(\bcat\b|\bls\b|\bwhoami\b|\bpwd\b)`),
                Severity:    4,
                Description: "Command injection attempt",
            },
            
            // File Upload
            {
                Name:        "MALICIOUS_FILE_UPLOAD",
                Regex:       regexp.MustCompile(`\.(php|jsp|asp|aspx|sh|bat|exe)$`),
                Severity:    3,
                Description: "Potentially malicious file upload",
            },
        },
    }
}

// Match checks if log line matches any pattern
func (pm *PatternMatcher) Match(line string) []PatternMatch {
    var matches []PatternMatch
    
    for _, pattern := range pm.patterns {
        if pattern.Regex.MatchString(line) {
            match := PatternMatch{
                PatternName: pattern.Name,
                Severity:    pattern.Severity,
                Description: pattern.Description,
                Line:        line,
                Matches:     pattern.Regex.FindStringSubmatch(line),
            }
            matches = append(matches, match)
        }
    }
    
    return matches
}

// PatternMatch represents a detected pattern
type PatternMatch struct {
    PatternName string
    Severity    int
    Description string
    Line        string
    Matches     []string  // Regex capture groups
}
```

### Unit Tests

Create `internal/sentry/patterns_test.go`:

```go
package sentry

import (
    "testing"
)

func TestPatternMatcher_SSH(t *testing.T) {
    pm := NewPatternMatcher()
    
    line := "Failed password for root from 192.168.1.100"
    matches := pm.Match(line)
    
    if len(matches) == 0 {
        t.Error("Expected SSH pattern match")
    }
    
    if matches[0].PatternName != "SSH_FAILED_PASSWORD" {
        t.Errorf("Expected SSH_FAILED_PASSWORD, got %s", matches[0].PatternName)
    }
    
    if len(matches[0].Matches) < 2 {
        t.Error("Expected IP address capture")
    }
}

func TestPatternMatcher_SQLi(t *testing.T) {
    pm := NewPatternMatcher()
    
    tests := []struct {
        line     string
        expected string
    }{
        {"SELECT * FROM users WHERE id=1 UNION SELECT password", "SQLI_UNION"},
        {"admin'--", "SQLI_COMMENT"},
    }
    
    for _, tt := range tests {
        matches := pm.Match(tt.line)
        if len(matches) == 0 {
            t.Errorf("No match for: %s", tt.line)
            continue
        }
        if matches[0].PatternName != tt.expected {
            t.Errorf("Expected %s, got %s", tt.expected, matches[0].PatternName)
        }
    }
}

func TestPatternMatcher_XSS(t *testing.T) {
    pm := NewPatternMatcher()
    
    line := `<script>alert('XSS')</script>`
    matches := pm.Match(line)
    
    if len(matches) == 0 {
        t.Error("Expected XSS pattern match")
    }
}

func TestPatternMatcher_PathTraversal(t *testing.T) {
    pm := NewPatternMatcher()
    
    line := "GET ../../etc/passwd HTTP/1.1"
    matches := pm.Match(line)
    
    if len(matches) == 0 {
        t.Error("Expected path traversal match")
    }
}

func TestPatternMatcher_NoMatch(t *testing.T) {
    pm := NewPatternMatcher()
    
    line := "Normal log entry"
    matches := pm.Match(line)
    
    if len(matches) != 0 {
        t.Error("Expected no matches for normal log")
    }
}

func TestPatternMatcher_Count(t *testing.T) {
    pm := NewPatternMatcher()
    
    if len(pm.patterns) < 10 {
        t.Errorf("Expected at least 10 patterns, got %d", len(pm.patterns))
    }
}
```

## Success Criteria

```bash
# 1. Compiles
go build ./internal/sentry/

# 2. All tests pass
go test -v ./internal/sentry/
# Expected: All tests PASS

# 3. Pattern count check
# Should have 10+ patterns

# 4. Integration with LogWatcher
logEvent := <-watcher.Events()
matches := patternMatcher.Match(logEvent.Line)
if len(matches) > 0 {
    log.Printf("Threat detected: %s (severity: %d)", 
        matches[0].PatternName, matches[0].Severity)
}
```

## Deliverables
1. `internal/sentry/patterns.go` (10+ patterns)
2. `internal/sentry/patterns_test.go` (comprehensive tests)
3. All tests passing
4. Confirmation of 10+ security patterns

## Quality Checklist
- [ ] At least 10 patterns implemented
- [ ] All pattern categories covered (SSH, SQLi, XSS, etc.)
- [ ] All unit tests pass
- [ ] Severity levels assigned (1-4)
- [ ] Regex patterns tested with regex101.com

## Next Task
Task 1.3 - System metrics collector
```

**After Completion:**
```bash
# 1. Test
go test -v ./internal/sentry/
# All tests should PASS

# 2. Commit
git add internal/sentry/patterns*.go
git commit -m "feat(sentry): add security pattern matcher (Phase 1.2)"
git push

# 3. Update progress.md (mark 1.2 as 🟡 Implementation complete)
# 4. PROCEED TO QA REVIEW (below) - DO NOT skip for critical tasks!
```

---

### Task 1.2 - QA Test Review (CRITICAL - Required)

**Agent Role:** Test Agent (Gemini 3.1 Pro High or similar)  
**Prerequisites:** Task 1.2 implementation complete, basic tests passing

#### 📋 Prompt for Test Agent:

```markdown
# QA Test Review: WatchTower Phase 1.2 - Pattern Matcher

## Context
I completed Task 1.2 (security pattern matcher) with basic tests.
Now I need independent test review to find bugs and coverage gaps.

## Code to Review

### patterns.go
[PASTE YOUR internal/sentry/patterns.go CODE HERE]

### patterns_test.go (existing)
[PASTE YOUR internal/sentry/patterns_test.go CODE HERE]

## Your Task

You are an independent QA engineer. Review this code and find:

1. **Coverage Analysis**
   - Which functions are tested?
   - Which code paths are NOT tested?
   - Estimated coverage %?

2. **Missing Test Cases**
   List specific tests that SHOULD exist but don't:
   - Edge cases (empty string, nil, very long input)
   - Boundary conditions
   - Multiple matches in one line
   - Unicode/binary input
   - False positives (normal text triggering patterns)
   - Capture group validation

3. **Bug Hunting**
   - Can you find inputs that break the patterns?
   - Any regex that's too broad or too narrow?
   - Performance issues (ReDoS risk)?

4. **Security Concerns**
   - Can attackers bypass these patterns?
   - Any false negative risks?
   - Input validation issues?

## Deliverables

### 1. Coverage Report
```
Function: NewPatternMatcher()
Status: ✅ Tested / ⚠️ Partial / ❌ Not tested
Missing: [specific scenarios]

Function: Match(line string)
Status: ✅ Tested / ⚠️ Partial / ❌ Not tested
Missing: [specific scenarios]
```

### 2. Bug Report
List any bugs found:
```
Bug #1: [Title]
Severity: Critical/High/Medium/Low
Description: [what's wrong]
Impact: [what could break]
Fix: [how to fix]
```

### 3. New Test Code
Write complete Go test functions for missing cases:
```go
func TestPatternMatcher_EdgeCaseXYZ(t *testing.T) {
    // Your test code
}
```

### 4. Recommendations
- Priority 1 (Must add): [critical tests]
- Priority 2 (Should add): [important tests]
- Priority 3 (Nice to have): [optional tests]

## Success Criteria

After adding your tests:
```bash
go test -v ./internal/sentry/
# All tests PASS

go test -cover ./internal/sentry/
# Coverage >80%

go test -race ./internal/sentry/
# No race conditions
```

## Expected Output

Provide:
1. Complete coverage analysis
2. List of bugs found (if any)
3. 5-10 new test functions (ready to paste)
4. Priority recommendations
```

**After QA Review:**
```bash
# 1. Review agent's findings
# 2. Fix any bugs found
# 3. Add new test functions to patterns_test.go
# 4. Test again
go test -v ./internal/sentry/
go test -cover ./internal/sentry/
# Should be >80%

# 5. Commit QA improvements
git add internal/sentry/patterns*.go
git commit -m "test(sentry): comprehensive test review (Phase 1.2)

QA Findings:
- Bugs found: X (all fixed)
- Tests added: Y new test functions
- Coverage: XX% → YY%

Reviewer: Gemini 3.1 Pro High"
git push

# 6. Update progress.md (mark 1.2 as 🟢 Test reviewed)
# 7. PROCEED TO SECURITY REVIEW (below)
```

---

### Task 1.2 - Security Review (CRITICAL - Required)

**Agent Role:** Security Agent (GitHub Codex, Claude fresh chat, or security specialist)  
**Prerequisites:** Task 1.2 QA review complete, coverage >80%

#### 📋 Prompt for Security Agent:

```markdown
# Security Review: WatchTower Phase 1.2 - Pattern Matcher

## Context
Security-critical component: regex pattern matcher for threat detection.
This code will process untrusted log input and trigger security alerts.

## Code to Review

### patterns.go
[PASTE YOUR internal/sentry/patterns.go CODE HERE]

### patterns_test.go
[PASTE YOUR internal/sentry/patterns_test.go CODE HERE]

## Security Review Checklist

You are a security auditor. Review for:

### 1. Input Validation
- [ ] No input length limits (DoS risk?)
- [ ] Unicode/binary input handled?
- [ ] Null byte injection possible?
- [ ] Very long strings (>10KB) tested?

### 2. Regular Expression Security
- [ ] ReDoS (catastrophic backtracking) risk?
- [ ] Patterns tested with malicious input?
- [ ] Timeouts on regex matching?
- [ ] Overly broad patterns (false positives)?
- [ ] Overly narrow patterns (bypasses)?

### 3. False Positives/Negatives
- [ ] Can legitimate traffic trigger alerts?
- [ ] Can attackers craft input to bypass detection?
- [ ] Edge cases that evade detection?

### 4. Resource Limits
- [ ] Memory usage bounded?
- [ ] CPU usage controlled?
- [ ] Pattern compilation cached?

### 5. Attack Scenarios
Test with malicious patterns:
```
1. ReDoS: "(a+)+" with "aaaaaaaaaaaaaaaaaaaX"
2. Unicode bypass: "admin\u0000" 
3. Encoding bypass: URL encoding, double encoding
4. Case bypass: mixed case variations
5. Whitespace bypass: extra spaces, tabs, newlines
```

## Vulnerability Assessment

For each finding, provide:

### Critical (Immediate fix required)
```
CVE-like ID: WatchTower-2026-001
Title: [Vulnerability name]
Severity: Critical
Component: [file:line]
Description: [what's wrong]
Attack Vector: [how to exploit]
Impact: [what attacker gains]
Proof of Concept: [code example]
Fix: [specific code changes]
```

### High/Medium/Low
Same format for each severity level.

## Deliverables

1. **Security Assessment Report**
   - Critical: X vulnerabilities
   - High: Y vulnerabilities
   - Medium: Z vulnerabilities
   - Low: N issues

2. **Proof of Concepts**
   - Code demonstrating each vulnerability
   - Expected vs actual behavior

3. **Remediation Code**
   - Specific code fixes for each issue
   - Ready to apply

4. **Security Tests**
   - New test functions for attack scenarios
   ```go
   func TestPatternMatcher_SecurityReDoS(t *testing.T) {
       // Anti-ReDoS test
   }
   ```

## Attack Test Cases

Test these specific attacks:

1. **ReDoS Attack:**
   ```go
   malicious := strings.Repeat("a", 10000) + "X"
   // Should complete in <100ms
   ```

2. **Bypass with Encoding:**
   ```go
   bypass := "admin%00--"
   bypass2 := "admin\x00--"
   ```

3. **Unicode Normalization:**
   ```go
   unicode := "ᴀdmin" // Using Unicode lookalikes
   ```

4. **Case Variation:**
   ```go
   mixed := "UnIoN SeLeCt"
   ```

5. **Whitespace Tricks:**
   ```go
   spaces := "union\t\nselect"
   ```

## Success Criteria

After fixes:
```bash
# No vulnerabilities
go test -v ./internal/sentry/ -run Security
# All security tests PASS

# Performance check
go test -bench=. ./internal/sentry/
# No patterns take >100ms

# Memory check
go test -memprofile=mem.out ./internal/sentry/
# No memory leaks
```
```

**After Security Review:**
```bash
# 1. Review security findings
# 2. Fix all Critical and High vulnerabilities
# 3. Add security tests
# 4. Re-test
go test -v ./internal/sentry/

# 5. Commit security hardening
git add internal/sentry/patterns*.go
git commit -m "security(sentry): harden pattern matcher (Phase 1.2)

Security Findings:
- Critical: X (all fixed)
- High: Y (all fixed)
- Medium: Z (mitigated)
- Low: N (documented)

Fixes:
- Add input length limit (10KB)
- Add regex timeout (100ms)
- Fix ReDoS in [pattern]
- Add Unicode normalization

Reviewer: GitHub Codex / Security Team"
git push

# 6. Update progress.md (mark 1.2 as ✅ Complete - Secured)
# 7. Move to Task 1.3
```

---

### Task 1.3 - System Metrics Collector

**Agent Role:** Code Agent  
**Prerequisites:** Task 1.2 complete (PatternMatcher working)

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 1.3 - System Metrics Collector

## Context
Project: WatchTower XDR
Component: WT-Sentry
Phase: 1.3 - System resource monitoring
Previous: Task 1.2 complete (PatternMatcher detects threats)

## Task
Create internal/sentry/metrics.go that collects CPU, memory, disk, and network metrics.

## Requirements

### 1. File to Create
`internal/sentry/metrics.go`

### 2. Dependencies
```bash
go get github.com/shirou/gopsutil/v3
```

### 3. Implementation

```go
package sentry

import (
    "context"
    "log"
    "time"
    
    "github.com/shirou/gopsutil/v3/cpu"
    "github.com/shirou/gopsutil/v3/disk"
    "github.com/shirou/gopsutil/v3/mem"
    "github.com/shirou/gopsutil/v3/net"
)

// SystemMetrics represents current system state
type SystemMetrics struct {
    Timestamp       int64
    CPUPercent      float64
    MemoryPercent   float64
    MemoryUsedMB    uint64
    DiskPercent     float64
    DiskUsedGB      uint64
    NetworkBytesSent uint64
    NetworkBytesRecv uint64
}

// MetricsCollector collects system metrics periodically
type MetricsCollector struct {
    interval time.Duration
    metrics  chan SystemMetrics
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(interval time.Duration) *MetricsCollector {
    return &MetricsCollector{
        interval: interval,
        metrics:  make(chan SystemMetrics, 10),
    }
}

// Start begins collecting metrics
func (mc *MetricsCollector) Start(ctx context.Context) {
    ticker := time.NewTicker(mc.interval)
    defer ticker.Stop()
    
    // Collect immediately
    mc.collectMetrics()
    
    // Then collect periodically
    go func() {
        for {
            select {
            case <-ticker.C:
                mc.collectMetrics()
            case <-ctx.Done():
                return
            }
        }
    }()
}

// collectMetrics gathers current system metrics
func (mc *MetricsCollector) collectMetrics() {
    // CPU
    cpuPercent, err := cpu.Percent(time.Second, false)
    if err != nil {
        log.Printf("Error getting CPU: %v", err)
        return
    }
    
    // Memory
    vmem, err := mem.VirtualMemory()
    if err != nil {
        log.Printf("Error getting memory: %v", err)
        return
    }
    
    // Disk (root partition)
    diskUsage, err := disk.Usage("/")
    if err != nil {
        log.Printf("Error getting disk: %v", err)
        return
    }
    
    // Network
    netIO, err := net.IOCounters(false)
    if err != nil {
        log.Printf("Error getting network: %v", err)
        return
    }
    
    metrics := SystemMetrics{
        Timestamp:       time.Now().Unix(),
        CPUPercent:      cpuPercent[0],
        MemoryPercent:   vmem.UsedPercent,
        MemoryUsedMB:    vmem.Used / 1024 / 1024,
        DiskPercent:     diskUsage.UsedPercent,
        DiskUsedGB:      diskUsage.Used / 1024 / 1024 / 1024,
        NetworkBytesSent: netIO[0].BytesSent,
        NetworkBytesRecv: netIO[0].BytesRecv,
    }
    
    mc.metrics <- metrics
}

// Metrics returns channel for receiving metrics
func (mc *MetricsCollector) Metrics() <-chan SystemMetrics {
    return mc.metrics
}

// Close stops the collector
func (mc *MetricsCollector) Close() {
    close(mc.metrics)
}
```

### 4. Unit Test

Create `internal/sentry/metrics_test.go`:

```go
package sentry

import (
    "context"
    "testing"
    "time"
)

func TestMetricsCollector_CollectsMetrics(t *testing.T) {
    collector := NewMetricsCollector(1 * time.Second)
    
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()
    
    collector.Start(ctx)
    
    // Wait for at least 2 metrics
    count := 0
    timeout := time.After(3 * time.Second)
    
    for count < 2 {
        select {
        case m := <-collector.Metrics():
            count++
            
            // Validate metrics
            if m.CPUPercent < 0 || m.CPUPercent > 100 {
                t.Errorf("Invalid CPU: %f", m.CPUPercent)
            }
            if m.MemoryPercent < 0 || m.MemoryPercent > 100 {
                t.Errorf("Invalid memory: %f", m.MemoryPercent)
            }
            if m.DiskPercent < 0 || m.DiskPercent > 100 {
                t.Errorf("Invalid disk: %f", m.DiskPercent)
            }
            
            t.Logf("Metrics: CPU=%.1f%%, Mem=%.1f%%, Disk=%.1f%%",
                m.CPUPercent, m.MemoryPercent, m.DiskPercent)
                
        case <-timeout:
            t.Fatal("Timeout waiting for metrics")
        }
    }
}

func TestMetricsCollector_Interval(t *testing.T) {
    interval := 500 * time.Millisecond
    collector := NewMetricsCollector(interval)
    
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()
    
    collector.Start(ctx)
    
    start := time.Now()
    <-collector.Metrics() // First metric (immediate)
    <-collector.Metrics() // Second metric (after interval)
    elapsed := time.Since(start)
    
    // Should be approximately 500ms (±200ms tolerance)
    if elapsed < 300*time.Millisecond || elapsed > 700*time.Millisecond {
        t.Errorf("Expected ~500ms interval, got %v", elapsed)
    }
}
```

## Success Criteria

```bash
# 1. Install dependency
go get github.com/shirou/gopsutil/v3
go mod tidy

# 2. Compiles
go build ./internal/sentry/

# 3. Tests pass
go test -v ./internal/sentry/
# Expected: PASS
# Should see output like:
# Metrics: CPU=15.2%, Mem=45.3%, Disk=68.9%

# 4. Manual test
collector := NewMetricsCollector(30 * time.Second)
collector.Start(ctx)

for metrics := range collector.Metrics() {
    fmt.Printf("CPU: %.1f%%, Memory: %.1f%%, Disk: %.1f%%\n",
        metrics.CPUPercent, metrics.MemoryPercent, metrics.DiskPercent)
}
# Should print metrics every 30 seconds
```

## Deliverables
1. `internal/sentry/metrics.go` (complete implementation)
2. `internal/sentry/metrics_test.go` (unit tests)
3. Confirmation tests pass
4. Metrics within valid ranges (0-100%)

## Quality Checklist
- [ ] All 4 metric types collected (CPU, memory, disk, network)
- [ ] Metrics within valid ranges (0-100% for percentages)
- [ ] Configurable interval (30 seconds default)
- [ ] Context-aware (stops on ctx.Done())
- [ ] No panics on missing data

## Next Task
Task 1.4 - gRPC Event Sender (integrate LogWatcher, PatternMatcher, MetricsCollector)
```

**After Completion:**
```bash
# 1. Install dependency
go get github.com/shirou/gopsutil/v3
go mod tidy

# 2. Test
go test -v ./internal/sentry/

# 3. Commit
git add internal/sentry/metrics*.go go.mod go.sum
git commit -m "feat(sentry): add system metrics collector (Phase 1.3)"
git push

# 4. Update progress.md (mark 1.3 as ✅)
# 5. Move to task 1.4
```

---

### Task 1.4 - gRPC Event Sender (Sentry)

**Agent Role:** Code Agent  
**Prerequisites:** Tasks 1.1-1.3 complete (LogWatcher, PatternMatcher, MetricsCollector)

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 1.4 - gRPC Event Sender

## Context
Project: WatchTower XDR
Component: WT-Sentry
Phase: 1.4 - Send detected events to Core via gRPC
Previous: Tasks 1.1-1.3 complete (LogWatcher, PatternMatcher, MetricsCollector working)

## Task
1. Update pkg/protocol/agent.proto to add SendEvent RPC
2. Recompile protobuf
3. Update cmd/wt-sentry/main.go to integrate all components and send events

## Requirements

### Step 1: Update Protocol

Update `pkg/protocol/agent.proto`:

```protobuf
syntax = "proto3";
package protocol;
option go_package = "github.com/EForce11/WatchTower/pkg/protocol";

message HeartbeatRequest {
  string agent_id = 1;
  int64 timestamp = 2;
}

message HeartbeatResponse {
  string status = 1;
  int64 server_time = 2;
}

// NEW: Event message
message EventRequest {
  string agent_id = 1;
  int64 timestamp = 2;
  string event_type = 3;
  int32 severity = 4;
  string source_ip = 5;
  string source_file = 6;
  string message = 7;
  string metadata = 8;  // JSON string
}

message EventResponse {
  string status = 1;
  string event_id = 2;
}

service AgentService {
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc SendEvent(EventRequest) returns (EventResponse);  // NEW
}
```

### Step 2: Recompile Protobuf

```bash
protoc --go_out=. --go-grpc_out=. pkg/protocol/agent.proto
go mod tidy
```

### Step 3: Update Sentry Main

Update `cmd/wt-sentry/main.go` to integrate all components:

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"
    
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    
    pb "github.com/EForce11/WatchTower/pkg/protocol"
    "github.com/EForce11/WatchTower/internal/sentry"
)

const (
    coreAddress = "localhost:50051"
    agentID     = "sentry-test-001"
)

func main() {
    // Setup signal handling
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    
    go func() {
        <-sigChan
        log.Println("Shutting down...")
        cancel()
    }()
    
    // Connect to Core
    conn, err := grpc.Dial(coreAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()
    
    client := pb.NewAgentServiceClient(conn)
    log.Printf("Connected to Core at %s", coreAddress)
    
    // Start components
    logWatcher, err := sentry.NewLogWatcher([]string{"/var/log/auth.log"})
    if err != nil {
        log.Fatalf("Failed to create log watcher: %v", err)
    }
    defer logWatcher.Close()
    logWatcher.Watch(ctx)
    
    patternMatcher := sentry.NewPatternMatcher()
    
    metricsCollector := sentry.NewMetricsCollector(30 * time.Second)
    metricsCollector.Start(ctx)
    
    // Process events
    go handleLogEvents(ctx, client, logWatcher, patternMatcher)
    go handleMetrics(ctx, client, metricsCollector)
    go sendHeartbeats(ctx, client)
    
    <-ctx.Done()
    log.Println("Shutdown complete")
}

func handleLogEvents(ctx context.Context, client pb.AgentServiceClient, 
                     watcher *sentry.LogWatcher, matcher *sentry.PatternMatcher) {
    for {
        select {
        case event := <-watcher.Events():
            matches := matcher.Match(event.Line)
            for _, match := range matches {
                sendEvent(client, match.PatternName, match.Severity, 
                         event.FilePath, event.Line, match.Matches)
            }
        case <-ctx.Done():
            return
        }
    }
}

func handleMetrics(ctx context.Context, client pb.AgentServiceClient, 
                   collector *sentry.MetricsCollector) {
    for {
        select {
        case metrics := <-collector.Metrics():
            // Send high CPU/memory alerts
            if metrics.CPUPercent > 80 {
                sendEvent(client, "SYSTEM_CPU_HIGH", 2, "system", 
                         "CPU usage high", []string{})
            }
            if metrics.MemoryPercent > 80 {
                sendEvent(client, "SYSTEM_MEMORY_HIGH", 2, "system", 
                         "Memory usage high", []string{})
            }
        case <-ctx.Done():
            return
        }
    }
}

func sendEvent(client pb.AgentServiceClient, eventType string, severity int, 
               sourceFile, message string, matches []string) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    metadata, _ := json.Marshal(map[string]interface{}{
        "matches": matches,
    })
    
    req := &pb.EventRequest{
        AgentId:    agentID,
        Timestamp:  time.Now().Unix(),
        EventType:  eventType,
        Severity:   int32(severity),
        SourceFile: sourceFile,
        Message:    message,
        Metadata:   string(metadata),
    }
    
    // Extract source IP if available
    if len(matches) > 1 {
        req.SourceIp = matches[1]
    }
    
    resp, err := client.SendEvent(ctx, req)
    if err != nil {
        log.Printf("Failed to send event: %v", err)
        return
    }
    
    log.Printf("Event sent: %s (severity: %d, id: %s)", 
               eventType, severity, resp.EventId)
}

func sendHeartbeats(ctx context.Context, client pb.AgentServiceClient) {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            hbCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
            req := &pb.HeartbeatRequest{
                AgentId:   agentID,
                Timestamp: time.Now().Unix(),
            }
            _, err := client.Heartbeat(hbCtx, req)
            cancel()
            
            if err != nil {
                log.Printf("Heartbeat failed: %v", err)
            }
        case <-ctx.Done():
            return
        }
    }
}
```

## Success Criteria

```bash
# 1. Protobuf recompiled
protoc --go_out=. --go-grpc_out=. pkg/protocol/agent.proto
ls pkg/protocol/agent.pb.go  # Should show updated file

# 2. Builds successfully
go build cmd/wt-sentry/main.go

# 3. Starts without errors (Core must be running)
# Terminal 1: Core
go run cmd/wt-core/main.go

# Terminal 2: Sentry
go run cmd/wt-sentry/main.go
# Should output: "Connected to Core at localhost:50051"

# 4. Detects events
# Terminal 3: Trigger SSH failure
echo "Failed password for root from 192.168.1.100" >> /var/log/auth.log
# Sentry should log: "Event sent: SSH_FAILED_PASSWORD"

# 5. No crashes for 5 minutes
```

## Deliverables
1. Updated `pkg/protocol/agent.proto` (SendEvent RPC added)
2. Recompiled protobuf files
3. Updated `cmd/wt-sentry/main.go` (integrated components)
4. Confirmation Sentry sends events to Core

## Next Task
Task 1.5 - gRPC Event Receiver (Core side)
```

**After Completion:**
```bash
# Commit
git add pkg/protocol/ cmd/wt-sentry/
git commit -m "feat(sentry): integrate components and send events via gRPC (Phase 1.4)"
git push

# Update progress.md (mark 1.4 as 🟡 Implementation complete)
# PROCEED TO QA REVIEW (CRITICAL TASK!)
```

---

### Task 1.4 - QA Test Review (CRITICAL - Required)

**Agent Role:** Test Agent (Gemini 3.1 Pro High)  
**Prerequisites:** Task 1.4 implementation complete, events being sent

#### 📋 Prompt for Test Agent:

```markdown
# QA Test Review: WatchTower Phase 1.4 - gRPC Event Sender

## Context
Critical component: sends security events from Sentry to Core via gRPC.
Input validation bugs here could cause data loss or false alerts.

## Code to Review

### cmd/wt-sentry/main.go
[PASTE YOUR UPDATED cmd/wt-sentry/main.go]

### pkg/protocol/agent.proto (updated)
[PASTE YOUR UPDATED agent.proto]

## Your Task

Find issues in:

1. **Event Sending Logic**
   - What happens if Core is down?
   - What if gRPC times out?
   - Memory leaks from goroutines?
   - Channel blocking/deadlocks?

2. **Input Validation**
   - Are all EventRequest fields validated?
   - Empty/nil handling?
   - Very long messages (>1MB)?
   - Special characters in fields?

3. **Error Handling**
   - Network errors handled?
   - Retry logic tested?
   - Graceful degradation?

4. **Integration Testing**
   - Multiple events in quick succession?
   - Core restart during send?
   - Corrupted event data?

## Missing Test Cases

Write tests for:

1. **Network Failures:**
   ```go
   func TestEventSender_CoreUnreachable(t *testing.T)
   func TestEventSender_TimeoutHandling(t *testing.T)
   func TestEventSender_ReconnectAfterFailure(t *testing.T)
   ```

2. **Input Edge Cases:**
   ```go
   func TestEventSender_EmptyFields(t *testing.T)
   func TestEventSender_VeryLongMessage(t *testing.T)
   func TestEventSender_SpecialCharacters(t *testing.T)
   ```

3. **Concurrency:**
   ```go
   func TestEventSender_HighThroughput(t *testing.T)
   func TestEventSender_NoGoroutineLeak(t *testing.T)
   ```

## Deliverables

1. Bug report (if any)
2. 5-10 new test functions
3. Integration test scenarios
4. Performance recommendations

## Success Criteria

```bash
# Tests pass
go test -v ./cmd/wt-sentry/

# No race conditions
go test -race ./cmd/wt-sentry/

# No goroutine leaks
go test -v ./cmd/wt-sentry/ -run Goroutine
```
```

**After QA Review:**
```bash
# Add tests, fix bugs
git add cmd/wt-sentry/ test/
git commit -m "test(sentry): comprehensive event sender tests (Phase 1.4)

QA Findings:
- Bugs: [list]
- Tests added: [count]

Reviewer: Gemini 3.1 Pro High"
git push

# Update progress.md (mark 1.4 as 🟢 Test reviewed)
# Optional: Proceed to security review
```

---

### Task 1.4 - Security Review (Optional but Recommended)

**Agent Role:** Security Agent (GitHub Codex)  
**Prerequisites:** Task 1.4 QA complete

#### 📋 Prompt for Security Agent:

```markdown
# Security Review: WatchTower Phase 1.4 - gRPC Event Sender

## Security Concerns

1. **Injection Attacks**
   - Can attacker inject malicious data in EventRequest?
   - Protobuf serialization safe?
   - Metadata field sanitized?

2. **Resource Exhaustion**
   - Can attacker flood with events (DoS)?
   - Rate limiting needed?
   - Memory usage bounded?

3. **Data Integrity**
   - Event tampering possible?
   - Man-in-the-middle (no TLS yet)?
   - Event replay attacks?

## Test These Attacks

```go
// 1. Malicious metadata
malicious := map[string]interface{}{
    "exploit": strings.Repeat("A", 1000000), // 1MB
}

// 2. Event flood
for i := 0; i < 10000; i++ {
    sendEvent(...)
}

// 3. Special characters
message := "'; DROP TABLE events; --"
```

## Deliverables

1. Vulnerability report
2. Attack test cases
3. Recommended fixes (rate limiting, input validation)
```

**After Security Review (if done):**
```bash
git commit -m "security(sentry): harden event sender (Phase 1.4)"
git push
# Update progress.md (mark 1.4 as ✅ Complete)
```

---

### Task 1.5 - gRPC Event Receiver (Core)

**Agent Role:** Code Agent  
**Prerequisites:** Task 1.4 complete (Sentry sends events)

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 1.5 - gRPC Event Receiver

## Context
Project: WatchTower XDR
Component: WT-Core
Phase: 1.5 - Receive events from Sentry agents
Previous: Task 1.4 complete (Sentry sends EventRequest via gRPC)

## Task
1. Create internal/core/receiver.go
2. Update cmd/wt-core/main.go to implement SendEvent RPC

## Requirements

### Step 1: Create Event Receiver

Create `internal/core/receiver.go`:

```go
package core

import (
    "context"
    "log"
    "time"
    
    pb "github.com/EForce11/WatchTower/pkg/protocol"
    "github.com/google/uuid"
)

// EventReceiver handles incoming events from agents
type EventReceiver struct {
    events chan *pb.EventRequest
}

// NewEventReceiver creates a new event receiver
func NewEventReceiver() *EventReceiver {
    return &EventReceiver{
        events: make(chan *pb.EventRequest, 100),
    }
}

// HandleEvent processes an incoming event
func (er *EventReceiver) HandleEvent(ctx context.Context, req *pb.EventRequest) (*pb.EventResponse, error) {
    // Validate request
    if req.AgentId == "" {
        return nil, fmt.Errorf("agent_id required")
    }
    if req.EventType == "" {
        return nil, fmt.Errorf("event_type required")
    }
    
    // Generate event ID
    eventID := uuid.New().String()
    
    // Log event
    log.Printf("Event received: id=%s, agent=%s, type=%s, severity=%d, ip=%s",
        eventID, req.AgentId, req.EventType, req.Severity, req.SourceIp)
    
    // Send to processing channel
    select {
    case er.events <- req:
    default:
        log.Println("Warning: Event channel full, dropping event")
    }
    
    return &pb.EventResponse{
        Status:  "OK",
        EventId: eventID,
    }, nil
}

// Events returns channel for consuming events
func (er *EventReceiver) Events() <-chan *pb.EventRequest {
    return er.events
}
```

### Step 2: Update Core Main

Update `cmd/wt-core/main.go`:

```go
package main

import (
    "context"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
    
    "google.golang.org/grpc"
    pb "github.com/EForce11/WatchTower/pkg/protocol"
    "github.com/EForce11/WatchTower/internal/core"
)

type server struct {
    pb.UnimplementedAgentServiceServer
    eventReceiver *core.EventReceiver
}

func main() {
    // Setup
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    
    // Create event receiver
    eventReceiver := core.NewEventReceiver()
    
    // Process events
    go processEvents(ctx, eventReceiver)
    
    // Start gRPC server
    lis, err := net.Listen("tcp", ":50051")
    if err != nil {
        log.Fatalf("Failed to listen: %v", err)
    }
    
    grpcServer := grpc.NewServer()
    pb.RegisterAgentServiceServer(grpcServer, &server{
        eventReceiver: eventReceiver,
    })
    
    log.Println("Starting WatchTower Core on :50051")
    
    go func() {
        if err := grpcServer.Serve(lis); err != nil {
            log.Fatalf("Failed to serve: %v", err)
        }
    }()
    
    <-sigChan
    log.Println("Shutting down gracefully...")
    grpcServer.GracefulStop()
}

func (s *server) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
    log.Printf("Heartbeat from agent_id=%s, timestamp=%d", req.AgentId, req.Timestamp)
    return &pb.HeartbeatResponse{
        Status:     "OK",
        ServerTime: time.Now().Unix(),
    }, nil
}

func (s *server) SendEvent(ctx context.Context, req *pb.EventRequest) (*pb.EventResponse, error) {
    return s.eventReceiver.HandleEvent(ctx, req)
}

func processEvents(ctx context.Context, receiver *core.EventReceiver) {
    for {
        select {
        case event := <-receiver.Events():
            // For now, just log (Task 1.6 will write to PostgreSQL)
            log.Printf("Processing event: %s (severity: %d)", 
                       event.EventType, event.Severity)
        case <-ctx.Done():
            return
        }
    }
}
```

## Success Criteria

```bash
# 1. Builds
go build ./internal/core/
go build cmd/wt-core/main.go

# 2. Start Core
go run cmd/wt-core/main.go
# Output: "Starting WatchTower Core on :50051"

# 3. Start Sentry (in another terminal)
go run cmd/wt-sentry/main.go

# 4. Trigger event
echo "Failed password for root from 192.168.1.100" >> /var/log/auth.log

# Expected in Core logs:
# Event received: id=..., agent=sentry-test-001, type=SSH_FAILED_PASSWORD, severity=2, ip=192.168.1.100
# Processing event: SSH_FAILED_PASSWORD (severity: 2)

# Expected in Sentry logs:
# Event sent: SSH_FAILED_PASSWORD (severity: 2, id: ...)

# 5. No errors, events flow correctly
```

## Deliverables
1. `internal/core/receiver.go` (event handler)
2. Updated `cmd/wt-core/main.go` (implements SendEvent RPC)
3. Events successfully received and logged

## Next Task
Task 1.6 - PostgreSQL Event Writer (persist events to database)
```

**After Completion:**
```bash
# Commit
git add internal/core/ cmd/wt-core/
git commit -m "feat(core): implement event receiver (Phase 1.5)"
git push

# Update progress.md (mark 1.5 as ✅)
# Move to task 1.6
```

---

### Task 1.6 - PostgreSQL Event Writer

**Agent Role:** Code Agent  
**Prerequisites:** Task 1.5 complete (Core receives events), PostgreSQL installed

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 1.6 - PostgreSQL Event Writer

## Context
Project: WatchTower XDR
Component: WT-Core
Phase: 1.6 - Persist events to PostgreSQL database
Previous: Task 1.5 complete (Core receives and logs events)

## Pre-requisites

### PostgreSQL Setup

```sql
-- Create database
CREATE DATABASE watchtower;

-- Connect
\c watchtower

-- Create events table
CREATE TABLE events (
    id            BIGSERIAL PRIMARY KEY,
    timestamp     TIMESTAMP NOT NULL DEFAULT NOW(),
    agent_id      VARCHAR(255) NOT NULL,
    event_type    VARCHAR(100) NOT NULL,
    severity      INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 4),
    source_ip     VARCHAR(45),
    source_file   VARCHAR(500),
    message       TEXT,
    metadata      JSONB,
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX idx_events_agent_id ON events(agent_id);
CREATE INDEX idx_events_event_type ON events(event_type);
CREATE INDEX idx_events_severity ON events(severity);
```

## Task

### Step 1: Install Dependency

```bash
go get github.com/lib/pq
go mod tidy
```

### Step 2: Create Storage Module

Create `internal/core/storage.go`:

```go
package core

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "time"
    
    _ "github.com/lib/pq"
    pb "github.com/EForce11/WatchTower/pkg/protocol"
)

// EventStorage handles database operations for events
type EventStorage struct {
    db *sql.DB
}

// NewEventStorage creates a new event storage
func NewEventStorage(connStr string) (*EventStorage, error) {
    db, err := sql.Open("postgres", connStr)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %v", err)
    }
    
    // Test connection
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %v", err)
    }
    
    log.Println("Connected to PostgreSQL database")
    
    return &EventStorage{db: db}, nil
}

// WriteEvent writes an event to the database
func (es *EventStorage) WriteEvent(ctx context.Context, event *pb.EventRequest) error {
    query := `
        INSERT INTO events (timestamp, agent_id, event_type, severity, 
                          source_ip, source_file, message, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `
    
    timestamp := time.Unix(event.Timestamp, 0)
    
    _, err := es.db.ExecContext(ctx, query,
        timestamp,
        event.AgentId,
        event.EventType,
        event.Severity,
        event.SourceIp,
        event.SourceFile,
        event.Message,
        event.Metadata,
    )
    
    if err != nil {
        return fmt.Errorf("failed to write event: %v", err)
    }
    
    return nil
}

// Close closes the database connection
func (es *EventStorage) Close() error {
    return es.db.Close()
}
```

### Step 3: Create Test File

Create `internal/core/storage_test.go`:

```go
package core

import (
    "context"
    "os"
    "testing"
    "time"
    
    pb "github.com/EForce11/WatchTower/pkg/protocol"
)

func TestEventStorage_WriteEvent(t *testing.T) {
    // Skip if no database available
    connStr := os.Getenv("DATABASE_URL")
    if connStr == "" {
        connStr = "host=localhost user=postgres password=postgres dbname=watchtower sslmode=disable"
    }
    
    storage, err := NewEventStorage(connStr)
    if err != nil {
        t.Skipf("Database not available: %v", err)
    }
    defer storage.Close()
    
    // Create test event
    event := &pb.EventRequest{
        AgentId:    "test-agent",
        Timestamp:  time.Now().Unix(),
        EventType:  "TEST_EVENT",
        Severity:   2,
        SourceIp:   "192.168.1.100",
        SourceFile: "/var/log/test.log",
        Message:    "Test event",
        Metadata:   `{"test": true}`,
    }
    
    // Write event
    ctx := context.Background()
    err = storage.WriteEvent(ctx, event)
    if err != nil {
        t.Fatalf("Failed to write event: %v", err)
    }
    
    t.Log("Event written successfully")
}
```

### Step 4: Update Core Main

Update `cmd/wt-core/main.go` to use storage:

```go
// Add at top:
const (
    dbConnStr = "host=localhost user=postgres password=postgres dbname=watchtower sslmode=disable"
)

// In main():
// Create event storage
eventStorage, err := core.NewEventStorage(dbConnStr)
if err != nil {
    log.Fatalf("Failed to create storage: %v", err)
}
defer eventStorage.Close()

// Update processEvents:
func processEvents(ctx context.Context, receiver *core.EventReceiver, storage *core.EventStorage) {
    for {
        select {
        case event := <-receiver.Events():
            log.Printf("Processing event: %s (severity: %d)", 
                       event.EventType, event.Severity)
            
            // Write to database
            if err := storage.WriteEvent(ctx, event); err != nil {
                log.Printf("Failed to write event: %v", err)
            } else {
                log.Printf("Event written to database")
            }
        case <-ctx.Done():
            return
        }
    }
}

// Update go processEvents call:
go processEvents(ctx, eventReceiver, eventStorage)
```

## Success Criteria

```bash
# 1. PostgreSQL running
sudo systemctl status postgresql
# Should show: active (running)

# 2. Database created
psql -U postgres -d watchtower -c "\dt"
# Should show: events table

# 3. Builds
go build ./internal/core/
go build cmd/wt-core/main.go

# 4. Starts
go run cmd/wt-core/main.go
# Output: "Connected to PostgreSQL database"

# 5. Test event write
# Start Sentry in another terminal
go run cmd/wt-sentry/main.go

# Trigger event
echo "Failed password for root from 192.168.1.100" >> /var/log/auth.log

# Core should log:
# Event received: ...
# Processing event: SSH_FAILED_PASSWORD
# Event written to database

# 6. Verify in database
psql -U postgres -d watchtower -c "SELECT * FROM events ORDER BY id DESC LIMIT 5;"
# Should show recent events

# 7. No SQL errors
```

## Deliverables
1. `internal/core/storage.go` (PostgreSQL writer)
2. `internal/core/storage_test.go` (tests)
3. Updated `cmd/wt-core/main.go` (uses storage)
4. Events successfully written to PostgreSQL

## Troubleshooting

If PostgreSQL not installed:
```bash
# Ubuntu/Debian
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo -u postgres psql
```

If connection fails:
```bash
# Check PostgreSQL is listening
sudo netstat -tuln | grep 5432

# Check pg_hba.conf allows local connections
sudo nano /etc/postgresql/*/main/pg_hba.conf
# Add: host all all 127.0.0.1/32 md5
```

## Next Task
Task 1.7 - CLI Event Viewer (wt-cli events list)
```

**After Completion:**
```bash
# Commit
git add internal/core/ cmd/wt-core/ go.mod go.sum
git commit -m "feat(core): add PostgreSQL event storage (Phase 1.6)"
git push

# Update progress.md (mark 1.6 as 🟡 Implementation complete)
# PROCEED TO QA REVIEW - THIS IS CRITICAL (SQL INJECTION RISK!)
```

---

### Task 1.6 - QA Test Review (CRITICAL - MANDATORY)

**Agent Role:** Test Agent (Gemini 3.1 Pro High)  
**Prerequisites:** Task 1.6 complete, events writing to PostgreSQL

#### 📋 Prompt for Test Agent:

```markdown
# QA Test Review: WatchTower Phase 1.6 - PostgreSQL Event Storage

## ⚠️ CRITICAL SECURITY COMPONENT
This code writes to database with user input. SQL injection = critical vulnerability.

## Code to Review

### internal/core/storage.go
[PASTE YOUR storage.go CODE]

### internal/core/storage_test.go
[PASTE YOUR storage_test.go CODE]

## Your Task

### 1. SQL Injection Testing
**MOST IMPORTANT!** Test every field for SQL injection:

```go
// Test cases MUST include:
func TestStorage_SQLInjection_AgentID(t *testing.T) {
    malicious := "'; DROP TABLE events; --"
    event := &pb.EventRequest{AgentId: malicious, ...}
    // Should NOT execute DROP
}

func TestStorage_SQLInjection_EventType(t *testing.T)
func TestStorage_SQLInjection_Message(t *testing.T)
func TestStorage_SQLInjection_Metadata(t *testing.T)
```

### 2. Input Validation
- Null bytes in strings?
- Very long strings (>1MB)?
- Unicode characters?
- Binary data in text fields?

### 3. Database Edge Cases
- Connection loss during write?
- Transaction rollback handling?
- Deadlock scenarios?
- Concurrent writes?

### 4. Performance Testing
- Batch write performance?
- Index usage verified?
- Query plan optimization?

## Attack Scenarios to Test

```go
// 1. SQL Injection variants
"admin' OR '1'='1"
"1; UPDATE events SET severity=4; --"
"'; DROP TABLE events; --"
"admin'--"
"\x00admin"

// 2. XSS in stored data (later display)
"<script>alert('xss')</script>"

// 3. JSON injection in metadata
"{\"key\": \"'; DROP TABLE events; --\"}"

// 4. Buffer overflow attempts
strings.Repeat("A", 10000000) // 10MB
```

## Deliverables

1. **SQL Injection Test Suite** (10+ tests)
2. **Input Validation Tests**
3. **Concurrency Tests**
4. **Performance Benchmarks**

## Success Criteria

```bash
# All injection tests pass (no SQL execution!)
go test -v ./internal/core/ -run SQLInjection
# MUST PASS!

# No race conditions
go test -race ./internal/core/

# Performance acceptable
go test -bench=. ./internal/core/
# Write: <10ms per event
```
```

**After QA Review:**
```bash
# Fix ALL bugs found
# Add ALL test cases
git add internal/core/
git commit -m "test(core): comprehensive storage tests + SQL injection suite (Phase 1.6)

QA Findings:
- SQL Injection: [tested, safe/unsafe]
- Input validation: [tested]
- Performance: [benchmarks]

Reviewer: Gemini 3.1 Pro High"
git push

# Update progress.md (mark 1.6 as 🟢 Test reviewed)
# MANDATORY: Proceed to security review
```

---

### Task 1.6 - Security Review (CRITICAL - MANDATORY)

**Agent Role:** Security Agent (GitHub Codex + Manual Review)  
**Prerequisites:** Task 1.6 QA complete, SQL injection tests passing

#### 📋 Prompt for Security Agent:

```markdown
# Security Audit: WatchTower Phase 1.6 - PostgreSQL Storage

## ⚠️ HIGH RISK COMPONENT
Database layer with user-controlled input. Compromise = full system breach.

## Code to Audit

### internal/core/storage.go
[PASTE CODE]

## Security Checklist

### 1. SQL Injection (CRITICAL)
- [ ] Parameterized queries used? (REQUIRED)
- [ ] No string concatenation in SQL?
- [ ] All fields parameterized ($1, $2, etc)?
- [ ] Tested with malicious input?

**VERIFY THIS CODE:**
```go
query := `
    INSERT INTO events (timestamp, agent_id, event_type, ...)
    VALUES ($1, $2, $3, ...)  // ✅ GOOD
`
// NOT THIS:
query := fmt.Sprintf("INSERT INTO events VALUES ('%s')", event.AgentId) // ❌ BAD!
```

### 2. Input Validation
- [ ] Length limits enforced?
- [ ] Type checking?
- [ ] Null byte filtering?
- [ ] Unicode normalization?

### 3. Access Control
- [ ] Database user has minimal privileges?
- [ ] No DROP/ALTER/DELETE permissions?
- [ ] Connection string secured?
- [ ] Credentials not hardcoded?

### 4. Data Integrity
- [ ] Transactions used where needed?
- [ ] Foreign key constraints?
- [ ] Unique constraints?
- [ ] Audit logging?

### 5. Error Handling
- [ ] SQL errors don't leak schema info?
- [ ] No stack traces to client?
- [ ] Sensitive data not logged?

## Penetration Testing

### Test 1: Direct SQL Injection
```go
// Try to break out of parameterized query
malicious := []string{
    "'; DROP TABLE events; --",
    "1' OR '1'='1",
    "admin'--",
    "'; UPDATE events SET severity=4; --",
}

for _, input := range malicious {
    event := &pb.EventRequest{AgentId: input}
    err := storage.WriteEvent(ctx, event)
    // Should: err != nil OR data safely escaped
    // Should NOT: Execute malicious SQL
}
```

### Test 2: Second-Order SQL Injection
```go
// Store malicious data
event1 := &pb.EventRequest{AgentId: "admin' OR '1'='1"}
storage.WriteEvent(ctx, event1)

// Later retrieval should be safe
rows := db.Query("SELECT * FROM events WHERE agent_id = $1", "admin' OR '1'='1")
// Should return 1 row, not all rows
```

### Test 3: Blind SQL Injection
```go
// Time-based
event := &pb.EventRequest{
    AgentId: "admin'; SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END; --",
}
start := time.Now()
storage.WriteEvent(ctx, event)
elapsed := time.Since(start)
// Should: <100ms (no sleep executed)
```

### Test 4: NoSQL Injection (JSONB)
```go
// Metadata field uses JSONB
malicious := `{"$ne": null}`
event := &pb.EventRequest{Metadata: malicious}
storage.WriteEvent(ctx, event)
// Should be safely stored as string, not executed
```

## Vulnerability Report Template

```
Vulnerability: SQL Injection in AgentID field
Severity: CRITICAL
CWE: CWE-89
CVSS: 9.8 (Critical)

Description:
The WriteEvent function concatenates user input directly into SQL query...

Proof of Concept:
[code]

Impact:
- Attacker can read/modify/delete all database data
- Potential privilege escalation
- Data exfiltration

Remediation:
Use parameterized queries with $1, $2 placeholders.

Fixed Code:
[example]
```

## Deliverables

1. **Penetration Test Results**
   - All injection attempts documented
   - Pass/Fail for each test

2. **Vulnerability Report**
   - Critical/High/Medium/Low findings
   - Proof of concepts
   - Remediation code

3. **Security Tests**
   ```go
   func TestStorage_Security_SQLInjection(t *testing.T)
   func TestStorage_Security_AccessControl(t *testing.T)
   func TestStorage_Security_DataLeakage(t *testing.T)
   ```

4. **Recommendations**
   - Hardening checklist
   - Database configuration
   - Monitoring suggestions

## Success Criteria

```bash
# All security tests PASS
go test -v ./internal/core/ -run Security

# No vulnerabilities
- Critical: 0
- High: 0
- Medium: 0 (or documented + mitigated)

# Ready for production
[ ] SQL injection: SAFE
[ ] Access control: SECURE
[ ] Error handling: NO LEAKS
[ ] Input validation: COMPREHENSIVE
```
```

**After Security Review:**
```bash
# Fix ALL Critical and High vulnerabilities
# Add all security tests
# Re-test everything

git add internal/core/
git commit -m "security(core): comprehensive database hardening (Phase 1.6)

Security Audit Results:
- SQL Injection: SAFE (parameterized queries)
- Input Validation: COMPREHENSIVE
- Access Control: CONFIGURED
- Vulnerabilities: 0 Critical, 0 High

Tested Attacks:
- Direct SQL injection (12 variants)
- Second-order injection
- Blind SQL injection
- JSONB injection
- All BLOCKED ✅

Reviewer: GitHub Codex + Manual Security Review
Approved By: [Your Name]"

git push

# Update progress.md (mark 1.6 as ✅ Complete + Secured)
# Task 1.6 DONE - Can proceed to 1.7
```

---

### Task 1.7 - CLI Event Viewer

**Agent Role:** Code Agent  
**Prerequisites:** Task 1.6 complete (Events in PostgreSQL)

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 1.7 - CLI Event Viewer

## Context
Project: WatchTower XDR
Component: wt-cli
Phase: 1.7 - Query and display events from database
Previous: Task 1.6 complete (Events stored in PostgreSQL)

## Task
Create cmd/wt-cli/events.go that queries and displays events.

## Requirements

### Implementation

Create `cmd/wt-cli/events.go`:

```go
package main

import (
    "database/sql"
    "fmt"
    "os"
    "time"
    
    _ "github.com/lib/pq"
)

const (
    dbConnStr = "host=localhost user=postgres password=postgres dbname=watchtower sslmode=disable"
)

func main() {
    if len(os.Args) < 2 {
        printUsage()
        os.Exit(1)
    }
    
    command := os.Args[1]
    
    switch command {
    case "events":
        if len(os.Args) < 3 {
            printUsage()
            os.Exit(1)
        }
        subcommand := os.Args[2]
        
        switch subcommand {
        case "list":
            listEvents()
        default:
            printUsage()
            os.Exit(1)
        }
    default:
        printUsage()
        os.Exit(1)
    }
}

func printUsage() {
    fmt.Println("WatchTower CLI")
    fmt.Println("")
    fmt.Println("Usage:")
    fmt.Println("  wt-cli events list [--limit N] [--severity N] [--type TYPE]")
    fmt.Println("")
    fmt.Println("Examples:")
    fmt.Println("  wt-cli events list")
    fmt.Println("  wt-cli events list --limit 10")
    fmt.Println("  wt-cli events list --severity 4")
    fmt.Println("  wt-cli events list --type SSH_FAILED_PASSWORD")
}

func listEvents() {
    // Parse flags
    limit := 50
    severity := 0
    eventType := ""
    
    for i := 3; i < len(os.Args); i++ {
        switch os.Args[i] {
        case "--limit":
            if i+1 < len(os.Args) {
                fmt.Sscanf(os.Args[i+1], "%d", &limit)
                i++
            }
        case "--severity":
            if i+1 < len(os.Args) {
                fmt.Sscanf(os.Args[i+1], "%d", &severity)
                i++
            }
        case "--type":
            if i+1 < len(os.Args) {
                eventType = os.Args[i+1]
                i++
            }
        }
    }
    
    // Connect to database
    db, err := sql.Open("postgres", dbConnStr)
    if err != nil {
        fmt.Printf("Error connecting to database: %v\n", err)
        os.Exit(1)
    }
    defer db.Close()
    
    // Build query
    query := "SELECT id, timestamp, agent_id, event_type, severity, source_ip, message FROM events"
    args := []interface{}{}
    conditions := []string{}
    
    if severity > 0 {
        conditions = append(conditions, fmt.Sprintf("severity = $%d", len(args)+1))
        args = append(args, severity)
    }
    
    if eventType != "" {
        conditions = append(conditions, fmt.Sprintf("event_type = $%d", len(args)+1))
        args = append(args, eventType)
    }
    
    if len(conditions) > 0 {
        query += " WHERE " + conditions[0]
        for i := 1; i < len(conditions); i++ {
            query += " AND " + conditions[i]
        }
    }
    
    query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d", len(args)+1)
    args = append(args, limit)
    
    // Execute query
    rows, err := db.Query(query, args...)
    if err != nil {
        fmt.Printf("Error querying events: %v\n", err)
        os.Exit(1)
    }
    defer rows.Close()
    
    // Print header
    fmt.Printf("%-5s %-20s %-20s %-30s %-8s %-15s %s\n",
        "ID", "Timestamp", "Agent", "Type", "Severity", "Source IP", "Message")
    fmt.Println("---------------------------------------------------------------------------------------------------")
    
    // Print rows
    count := 0
    for rows.Next() {
        var id int64
        var timestamp time.Time
        var agentID, eventType, sourceIP, message string
        var severity int
        
        err := rows.Scan(&id, &timestamp, &agentID, &eventType, &severity, &sourceIP, &message)
        if err != nil {
            fmt.Printf("Error scanning row: %v\n", err)
            continue
        }
        
        // Truncate long messages
        if len(message) > 50 {
            message = message[:47] + "..."
        }
        
        fmt.Printf("%-5d %-20s %-20s %-30s %-8d %-15s %s\n",
            id, timestamp.Format("2006-01-02 15:04:05"),
            agentID, eventType, severity, sourceIP, message)
        
        count++
    }
    
    if count == 0 {
        fmt.Println("No events found")
    } else {
        fmt.Printf("\nTotal: %d events\n", count)
    }
}
```

## Success Criteria

```bash
# 1. Builds
go build -o wt-cli cmd/wt-cli/events.go

# 2. Shows usage
./wt-cli
# Output: "WatchTower CLI ... Usage: ..."

# 3. Lists all events
./wt-cli events list
# Output: Table with recent events

# 4. Limit works
./wt-cli events list --limit 10
# Output: At most 10 events

# 5. Severity filter works
./wt-cli events list --severity 4
# Output: Only severity 4 (critical) events

# 6. Type filter works
./wt-cli events list --type SSH_FAILED_PASSWORD
# Output: Only SSH failed password events

# 7. Combined filters work
./wt-cli events list --severity 2 --type SSH_FAILED_PASSWORD --limit 5
# Output: Max 5 SSH failed password events with severity 2

# 8. No events message
# (If no events match)
# Output: "No events found"
```

## Deliverables
1. `cmd/wt-cli/events.go` (complete CLI tool)
2. Built binary: `wt-cli`
3. All command-line options working
4. Clean, formatted output

## Example Output

```
ID    Timestamp            Agent                Type                           Severity Source IP       Message
---------------------------------------------------------------------------------------------------
15    2026-02-08 16:30:45  sentry-test-001      SSH_FAILED_PASSWORD           2        192.168.1.100   Failed password for root...
14    2026-02-08 16:30:30  sentry-test-001      SSH_FAILED_PASSWORD           2        192.168.1.100   Failed password for admin...
13    2026-02-08 16:25:15  sentry-test-001      SYSTEM_CPU_HIGH               2                        CPU usage high
12    2026-02-08 16:20:00  sentry-test-001      SSH_INVALID_USER              2        10.0.0.50       Invalid user test...

Total: 4 events
```

## Next Task
Task 1.8 - Integration Test (end-to-end test for Phase 1)
```

**After Completion:**
```bash
# Install to system PATH (optional)
go build -o wt-cli cmd/wt-cli/events.go
sudo mv wt-cli /usr/local/bin/

# Or add to Makefile
make build-cli

# Commit
git add cmd/wt-cli/
git commit -m "feat(cli): add event viewer (Phase 1.7)"
git push

# Update progress.md (mark 1.7 as ✅)
# Move to task 1.8 (FINAL TASK!)
```

---

### Task 1.8 - Integration Test (Phase 1)

**Agent Role:** Code Agent (Test-focused)  
**Prerequisites:** Tasks 1.1-1.7 complete (Full Phase 1 implemented)

#### 📋 Prompt for Code Agent:

```markdown
# Task: WatchTower Phase 1.8 - Integration Test

## Context
Project: WatchTower XDR
Phase: 1.8 - End-to-end test for Phase 1
Previous: Tasks 1.1-1.7 complete (all components working)

## Task
Create test/integration/phase1_test.go that verifies the complete event flow:
Log line → Detection → gRPC → PostgreSQL → CLI display

## Requirements

### Implementation

Create `test/integration/phase1_test.go`:

```go
package integration

import (
    "context"
    "database/sql"
    "fmt"
    "os"
    "os/exec"
    "testing"
    "time"
    
    _ "github.com/lib/pq"
)

const (
    dbConnStr = "host=localhost user=postgres password=postgres dbname=watchtower sslmode=disable"
)

func TestPhase1_EventFlow(t *testing.T) {
    // Test timeout
    ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
    defer cancel()
    
    // Clean database
    if err := cleanDatabase(); err != nil {
        t.Fatalf("Failed to clean database: %v", err)
    }
    
    // Create test log file
    logFile := "/tmp/watchtower-test.log"
    if err := os.WriteFile(logFile, []byte(""), 0644); err != nil {
        t.Fatalf("Failed to create log file: %v", err)
    }
    defer os.Remove(logFile)
    
    // Start Core
    t.Log("Starting Core...")
    coreCmd := exec.CommandContext(ctx, "go", "run", "../../cmd/wt-core/main.go")
    if err := coreCmd.Start(); err != nil {
        t.Fatalf("Failed to start Core: %v", err)
    }
    defer coreCmd.Process.Kill()
    
    // Wait for Core to be ready
    time.Sleep(3 * time.Second)
    
    // Start Sentry (modified to use test log file)
    t.Log("Starting Sentry...")
    sentryCmd := exec.CommandContext(ctx, "go", "run", "../../cmd/wt-sentry/main.go")
    sentryCmd.Env = append(os.Environ(), "WATCHTOWER_LOG_PATH="+logFile)
    if err := sentryCmd.Start(); err != nil {
        t.Fatalf("Failed to start Sentry: %v", err)
    }
    defer sentryCmd.Process.Kill()
    
    // Wait for Sentry to connect
    time.Sleep(2 * time.Second)
    
    // Simulate SSH brute force attack
    t.Log("Simulating SSH brute force...")
    attacks := []string{
        "Failed password for root from 192.168.1.100",
        "Failed password for admin from 192.168.1.101",
        "Invalid user test from 192.168.1.102",
        "Failed password for root from 192.168.1.100",
        "Failed password for root from 192.168.1.100",
    }
    
    f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        t.Fatalf("Failed to open log file: %v", err)
    }
    
    for _, attack := range attacks {
        if _, err := f.WriteString(attack + "\n"); err != nil {
            t.Fatalf("Failed to write attack: %v", err)
        }
        f.Sync()
        time.Sleep(500 * time.Millisecond)
    }
    f.Close()
    
    // Wait for events to be processed
    t.Log("Waiting for event processing...")
    time.Sleep(5 * time.Second)
    
    // Verify events in database
    db, err := sql.Open("postgres", dbConnStr)
    if err != nil {
        t.Fatalf("Failed to connect to database: %v", err)
    }
    defer db.Close()
    
    var count int
    err = db.QueryRow("SELECT COUNT(*) FROM events WHERE event_type LIKE 'SSH%'").Scan(&count)
    if err != nil {
        t.Fatalf("Failed to query events: %v", err)
    }
    
    t.Logf("Found %d SSH events in database", count)
    
    if count < 3 {
        t.Errorf("Expected at least 3 SSH events, got %d", count)
    }
    
    // Test CLI
    t.Log("Testing CLI...")
    cliCmd := exec.Command("go", "run", "../../cmd/wt-cli/events.go", "events", "list", "--limit", "10")
    output, err := cliCmd.CombinedOutput()
    if err != nil {
        t.Fatalf("CLI failed: %v\nOutput: %s", err, output)
    }
    
    outputStr := string(output)
    if !contains(outputStr, "SSH_FAILED_PASSWORD") && !contains(outputStr, "SSH_INVALID_USER") {
        t.Errorf("CLI output doesn't contain SSH events:\n%s", outputStr)
    }
    
    t.Log("✅ Phase 1 integration test passed")
}

func cleanDatabase() error {
    db, err := sql.Open("postgres", dbConnStr)
    if err != nil {
        return err
    }
    defer db.Close()
    
    _, err = db.Exec("TRUNCATE TABLE events RESTART IDENTITY")
    return err
}

func contains(s, substr string) bool {
    return len(s) >= len(substr) && 
           (s == substr || len(s) > len(substr) && 
            (s[:len(substr)] == substr || 
             s[len(s)-len(substr):] == substr || 
             containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
    for i := 0; i <= len(s)-len(substr); i++ {
        if s[i:i+len(substr)] == substr {
            return true
        }
    }
    return false
}
```

## Success Criteria

```bash
# 1. PostgreSQL running and watchtower database exists
psql -U postgres -d watchtower -c "SELECT 1"

# 2. Test compiles
go test -c ./test/integration/

# 3. Test runs and passes
go test -v ./test/integration/phase1_test.go
# Expected output:
# === RUN   TestPhase1_EventFlow
# phase1_test.go:XX: Starting Core...
# phase1_test.go:XX: Starting Sentry...
# phase1_test.go:XX: Simulating SSH brute force...
# phase1_test.go:XX: Waiting for event processing...
# phase1_test.go:XX: Found 5 SSH events in database
# phase1_test.go:XX: Testing CLI...
# phase1_test.go:XX: ✅ Phase 1 integration test passed
# --- PASS: TestPhase1_EventFlow (15.23s)
# PASS

# 4. Test is reliable (run 3 times)
go test -v -count=3 ./test/integration/phase1_test.go
# All 3 runs should PASS

# 5. Verify database
psql -U postgres -d watchtower -c "SELECT COUNT(*) FROM events;"
# Should show events from test
```

## Deliverables
1. `test/integration/phase1_test.go` (complete integration test)
2. Test passes consistently
3. Verifies full event flow (Log → Detect → Send → Store → Query)

## Troubleshooting

**If test fails with "connection refused":**
- Ensure PostgreSQL is running
- Check Core starts on port 50051
- Check database connection string

**If test fails with "no events found":**
- Check Sentry is monitoring test log file
- Check PatternMatcher detects test patterns
- Check Core logs for received events
- Check PostgreSQL for written events

**If test is flaky:**
- Increase sleep times (more processing time)
- Check system resources (CPU/memory)
- Run with -v flag to see detailed logs

## Next Steps After This Task

✅ Phase 1 Complete!

1. Commit test:
   ```bash
   git add test/integration/phase1_test.go
   git commit -m "test: add Phase 1 integration test (1.8)"
   git push
   ```

2. Tag release:
   ```bash
   git tag -a v0.3.0 -m "Phase 1 complete: Log monitoring and event detection"
   git push origin v0.3.0
   ```

3. Update documentation:
   - Update progress.md (Phase 1: 100%)
   - Update README.md (mention Phase 1 features)
   - Create CHANGELOG.md entry

4. Celebrate! 🎉
   Phase 1 = Foundation complete!

5. Prepare for Phase 2:
   - TimescaleDB migration
   - Agent health monitoring
   - Grafana dashboards
   - ntfy notifications
```

**After Completion:**
```bash
# Final commits
git add test/integration/phase1_test.go
git commit -m "test: Phase 1 integration test (1.8)"
git push

# Tag v0.3.0
git tag -a v0.3.0 -m "Phase 1: Log monitoring and event detection"
git push origin v0.3.0

# Update progress.md
# Mark Phase 1: 100% ✅

# 🎉 Phase 1 COMPLETE! 🎉
```

---

## 📝 Quick Reference for Phase 1

### Task Status Symbols
- ⚡ NEXT TASK
- ✅ Complete
- 🔴 In Progress
- ⏳ Waiting
- 🔵 Not Started

### Workflow per Task
1. New Antigravity chat
2. Copy prompt from agents.md
3. Get code
4. Test locally
5. Commit
6. Update progress.md
7. Move to next task

### Phase 1 Checklist
- [ ] Task 1.1: LogWatcher (fsnotify)
- [ ] Task 1.2: PatternMatcher (regex)
- [ ] Task 1.3: MetricsCollector (gopsutil)
- [ ] Task 1.4: Event Sender (gRPC)
- [ ] Task 1.5: Event Receiver (Core)
- [ ] Task 1.6: PostgreSQL Storage
- [ ] Task 1.7: CLI Viewer
- [ ] Task 1.8: Integration Test
- [ ] Tag v0.3.0
- [ ] Phase 1 Complete! 🎉

---

**Last Updated:** 2026-02-08 (Phase 1 complete - all 8 tasks added)  
**Next Update:** When starting Phase 2  
**Version:** Complete Phase 0 + Phase 1

