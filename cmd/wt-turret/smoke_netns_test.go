//go:build netns

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"

	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

// TestServeSmoke runs the real binary in the (unshared) network namespace:
// a reflex ban is APPLIED, then panic-flush removes the table.
func TestServeSmoke(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "wt-turret")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cfgPath, sock := writeSmokeConfig(t, dir)

	cmd := exec.Command(bin, "serve", "--config", cfgPath)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	c := dialRetry(t, sock)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	req := &synapsev1.TurretRequest{Kind: &synapsev1.TurretRequest_Reflex{Reflex: &synapsev1.ReflexRequest{
		RequestId: "smoke-1", Action: synapsev1.Action_ACTION_BAN_TEMP, Target: "203.0.113.9", TtlSeconds: 60,
	}}}
	if err := synapsev1.WriteFrame(c, req); err != nil {
		t.Fatal(err)
	}
	var resp synapsev1.TurretResponse
	if err := synapsev1.ReadFrame(c, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.GetResult() != synapsev1.TurretResult_TURRET_RESULT_APPLIED {
		t.Fatalf("result = %v (%s), want APPLIED", resp.GetResult(), resp.GetDetail())
	}

	if !hasTable(t) {
		t.Fatal("table inet watchtower missing after APPLIED")
	}
	if code, _, stderr := runCmd(t, "panic-flush"); code != 0 {
		t.Fatalf("panic-flush code=%d stderr=%q", code, stderr)
	}
	if hasTable(t) {
		t.Fatal("table inet watchtower still present after panic-flush")
	}

	// SIGTERM shuts down cleanly (exit 0).
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not exit on SIGTERM")
	}
}

func writeSmokeConfig(t *testing.T, dir string) (cfgPath, sock string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "automation.pub")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	sock = filepath.Join(dir, "run", "turret.sock")
	cfg := "agent_id: smoke\ncore_endpoint: 10.0.0.1:50051\n" +
		"state_dir: " + filepath.Join(dir, "state") + "\n" +
		"socket_path: " + sock + "\nsocket_group: root\n" +
		"automation_key: " + keyPath + "\n" +
		"admin_keys_dir: " + filepath.Join(dir, "admin") + "\n" +
		"whitelist_file: " + filepath.Join(dir, "none") + "\n" +
		"allowed_uids: [" + strconv.Itoa(os.Getuid()) + "]\n"
	cfgPath = filepath.Join(dir, "turret.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, sock
}

func dialRetry(t *testing.T, sock string) net.Conn {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		c, err := net.Dial("unix", sock)
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial %s: %v", sock, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func hasTable(t *testing.T) bool {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tabs, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range tabs {
		if tb.Name == "watchtower" {
			return true
		}
	}
	return false
}
