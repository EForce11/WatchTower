package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

func echo(req *synapsev1.TurretRequest) *synapsev1.TurretResponse {
	return &synapsev1.TurretResponse{
		Id:     req.GetReflex().GetRequestId(),
		Result: synapsev1.TurretResult_TURRET_RESULT_APPLIED,
	}
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type srv struct {
	s    *Server
	path string
	stop func()
}

func start(t *testing.T, allowed []int) *srv {
	t.Helper()
	path := filepath.Join(t.TempDir(), "turret.sock")
	s, err := New(path, -1, allowed, echo, quiet)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return")
		}
	}
	t.Cleanup(cancel)
	return &srv{s, path, stop}
}

func dial(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func request(id string) *synapsev1.TurretRequest {
	return &synapsev1.TurretRequest{Kind: &synapsev1.TurretRequest_Reflex{Reflex: &synapsev1.ReflexRequest{RequestId: id}}}
}

func roundTrip(t *testing.T, c net.Conn, id string) (*synapsev1.TurretResponse, error) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := synapsev1.WriteFrame(c, request(id)); err != nil {
		return nil, err
	}
	var resp synapsev1.TurretResponse
	if err := synapsev1.ReadFrame(c, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// expectClosed asserts the server closes c without sending a response.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(make([]byte, 16))
	if n != 0 || err == nil {
		t.Fatalf("read %d bytes, err %v; want closed connection", n, err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("connection was not closed")
	}
}

func TestRoundTripMultipleFrames(t *testing.T) {
	s := start(t, []int{os.Getuid()})
	c := dial(t, s.path)
	for _, id := range []string{"a", "b"} {
		r, err := roundTrip(t, c, id)
		if err != nil || r.GetId() != id || r.GetResult() != synapsev1.TurretResult_TURRET_RESULT_APPLIED {
			t.Fatalf("resp = %v err = %v", r, err)
		}
	}
}

func TestGarbageClosesConnectionNextClientWorks(t *testing.T) {
	s := start(t, []int{os.Getuid()})
	c := dial(t, s.path)
	if _, err := c.Write([]byte{0, 0, 0, 5, 0xff, 0xff, 0xff, 0xff, 0xff}); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c)
	c2 := dial(t, s.path)
	if r, err := roundTrip(t, c2, "ok"); err != nil || r.GetId() != "ok" {
		t.Fatalf("resp = %v err = %v", r, err)
	}
}

func TestOversizedHeaderClosed(t *testing.T) {
	s := start(t, []int{os.Getuid()})
	c := dial(t, s.path)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 70000)
	if _, err := c.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c)
}

func TestNinthConnectionClosed(t *testing.T) {
	s := start(t, []int{os.Getuid()})
	held := make([]*net.UnixConn, 0, MaxConns)
	for i := range MaxConns {
		c := dial(t, s.path)
		if r, err := roundTrip(t, c, "x"); err != nil || r.GetId() != "x" { // proves it holds a slot
			t.Fatalf("conn %d: %v %v", i, r, err)
		}
		held = append(held, c)
	}
	expectClosed(t, dial(t, s.path))
	// Freeing a slot lets a new client in.
	_ = held[0].Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c := dial(t, s.path)
		if r, err := roundTrip(t, c, "y"); err == nil && r.GetId() == "y" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot never freed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestDisallowedUIDClosedWithoutResponse(t *testing.T) {
	s := start(t, []int{os.Getuid() + 1})
	c := dial(t, s.path)
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_ = synapsev1.WriteFrame(c, request("nope")) // may fail if already closed
	expectClosed(t, c)
}

func TestSocketMode(t *testing.T) {
	s := start(t, []int{os.Getuid()})
	fi, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 || fi.Mode().Type() != os.ModeSocket {
		t.Fatalf("mode = %v", fi.Mode())
	}
}

func TestCancelStopsServeAndRemovesSocket(t *testing.T) {
	s := start(t, []int{os.Getuid()})
	c := dial(t, s.path)
	if _, err := roundTrip(t, c, "a"); err != nil {
		t.Fatal(err)
	}
	s.stop() // active connection must not block shutdown
	if _, err := os.Lstat(s.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still present: %v", err)
	}
	expectClosed(t, c)
}

func TestStaleSocketReplacedButNotRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "turret.sock")
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	_ = old.Close() // leaves a stale socket file
	s, err := New(path, -1, []int{os.Getuid()}, echo, quiet)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	_ = s.ln.Close()

	reg := filepath.Join(dir, "regular")
	if err := os.WriteFile(reg, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(reg, -1, nil, echo, quiet); err == nil {
		t.Fatal("regular file accepted")
	}
	if b, _ := os.ReadFile(reg); string(b) != "keep" {
		t.Fatal("regular file was modified")
	}
	if _, err := New(filepath.Join(dir, "missing", "x.sock"), -1, nil, echo, quiet); err == nil {
		t.Fatal("missing parent accepted")
	}
	if _, err := New(filepath.Join(dir, "y.sock"), -1, nil, nil, quiet); err == nil {
		t.Fatal("nil handler accepted")
	}
}
