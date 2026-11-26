// Package server exposes the Turret engine on a Unix socket.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

// Server limits.
const (
	MaxConns     = 8
	ReadTimeout  = 10 * time.Second
	writeTimeout = 5 * time.Second
)

// Handler turns one request into one response.
type Handler func(*synapsev1.TurretRequest) *synapsev1.TurretResponse

// Server accepts framed Turret requests from allowed peer UIDs.
type Server struct {
	path    string
	ln      *net.UnixListener
	allowed map[int]struct{}
	h       Handler
	log     *slog.Logger
	slots   chan struct{}
	accept  func() (*net.UnixConn, error) // test seam; defaults to ln.AcceptUnix
	sleep   func(time.Duration)           // test seam; defaults to time.Sleep

	mu    sync.Mutex
	conns map[*net.UnixConn]struct{}
	wg    sync.WaitGroup
}

// New removes a stale socket at path (only if it is a socket), listens,
// sets mode 0660 and, when running as root, chowns it to root:gid. The
// parent directory must exist.
func New(path string, gid int, allowed []int, h Handler, log *slog.Logger) (*Server, error) {
	if h == nil {
		return nil, errors.New("server: nil handler")
	}
	if log == nil {
		log = slog.Default()
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != os.ModeSocket {
			return nil, fmt.Errorf("server: %s exists and is not a socket", path)
		}
		if err := checkStale(path); err != nil {
			return nil, err
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("server: remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("server: stat %s: %w", path, err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("server: listen: %w", err)
	}
	fail := func(err error) (*Server, error) {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return fail(fmt.Errorf("server: chmod socket: %w", err))
	}
	if os.Geteuid() == 0 && gid >= 0 {
		if err := os.Chown(path, 0, gid); err != nil {
			return fail(fmt.Errorf("server: chown socket: %w", err))
		}
	}
	set := make(map[int]struct{}, len(allowed))
	for _, u := range allowed {
		set[u] = struct{}{}
	}
	srv := &Server{
		path: path, ln: ln, allowed: set, h: h, log: log,
		slots: make(chan struct{}, MaxConns),
		conns: map[*net.UnixConn]struct{}{},
		sleep: time.Sleep,
	}
	srv.accept = ln.AcceptUnix
	return srv, nil
}

// checkStale refuses to touch a socket that something is still listening on.
func checkStale(path string) error {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = c.Close()
		return errors.New("server: turret already running (socket is live)")
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("server: probe existing socket %s: %w", path, err)
}

// nextBackoff doubles the accept retry delay from 5 ms up to 1 s.
func nextBackoff(d time.Duration) time.Duration {
	if d < 5*time.Millisecond {
		return 5 * time.Millisecond
	}
	return min(2*d, time.Second)
}

// isTransient reports accept errors worth retrying (resource exhaustion,
// aborted connections) as opposed to a closed listener.
func isTransient(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED, syscall.ENOBUFS, syscall.ENOMEM, syscall.EINTR} {
		if errors.Is(err, e) {
			return true
		}
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Serve accepts connections until ctx is done, then closes the listener and
// every active connection, waits for the handlers and removes the socket.
func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
		s.closeAll()
	}()
	var serveErr error
	var backoff time.Duration
	for {
		c, err := s.accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			if isTransient(err) {
				backoff = nextBackoff(backoff)
				s.log.Warn("turret accept failed; retrying", "err", err, "backoff", backoff)
				s.sleep(backoff)
				continue
			}
			serveErr = fmt.Errorf("server: accept: %w", err)
			break
		}
		backoff = 0
		select {
		case s.slots <- struct{}{}:
		default:
			s.log.Warn("turret connection limit reached; dropping connection")
			_ = c.Close()
			continue
		}
		if !s.track(c) { // shutting down
			<-s.slots
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go s.handle(c)
	}
	cancel()
	_ = s.ln.Close()
	s.closeAll()
	s.wg.Wait()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("remove socket", "err", err)
	}
	return serveErr
}

func (s *Server) track(c *net.UnixConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c *net.UnixConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

// closeAll closes active connections and refuses new ones.
func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
}

func peerUID(c *net.UnixConn) (int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		cred, gerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) //nolint:gosec // fd fits int
	}); err != nil {
		return 0, err
	}
	if gerr != nil {
		return 0, gerr
	}
	return int(cred.Uid), nil
}

func (s *Server) handle(c *net.UnixConn) {
	defer s.wg.Done()
	defer func() { <-s.slots }()
	defer s.untrack(c)
	defer c.Close()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("turret connection handler panic", "panic", fmt.Sprint(r))
		}
	}()

	uid, err := peerUID(c)
	if err != nil {
		s.log.Warn("turret peer credentials unavailable", "err", err)
		return
	}
	if _, ok := s.allowed[uid]; !ok {
		s.log.Warn("turret connection from disallowed uid", "uid", uid)
		return
	}
	for {
		_ = c.SetReadDeadline(time.Now().Add(ReadTimeout))
		var req synapsev1.TurretRequest
		if err := synapsev1.ReadFrame(c, &req); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.log.Warn("turret read frame", "uid", uid, "err", err)
			}
			return
		}
		resp := s.h(&req)
		_ = c.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err := synapsev1.WriteFrame(c, resp); err != nil {
			s.log.Warn("turret write frame", "uid", uid, "err", err)
			return
		}
	}
}
