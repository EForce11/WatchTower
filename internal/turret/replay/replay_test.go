package replay

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var now = time.Unix(1_800_000_000, 0)

func TestRecordSeenAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.json")
	c, err := Open(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Seen("a") {
		t.Fatal("empty cache saw a")
	}
	if err := c.Record("a", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !c.Seen("a") {
		t.Fatal("not seen after record")
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat: %v %v", st, err)
	}
	c2, err := Open(path, now)
	if err != nil || !c2.Seen("a") {
		t.Fatalf("reopen: %v", err)
	}
}

func TestOpenPrunesExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.json")
	c, _ := Open(path, now)
	if err := c.Record("a", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := c.Record("b", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c2, err := Open(path, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if c2.Seen("a") || !c2.Seen("b") {
		t.Fatal("prune mismatch")
	}
	b, _ := os.ReadFile(path)
	if string(b) != `{"b":`+strconv.FormatInt(now.Add(time.Hour).Unix(), 10)+`}` {
		t.Fatalf("file not pruned: %s", b)
	}
}

func TestCorruptFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, now); err == nil {
		t.Fatal("expected error")
	}
}

func TestLeftoverTmpIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.json")
	if err := os.WriteFile(path+".stale.tmp", []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Record("a", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	c2, err := Open(path, now)
	if err != nil || !c2.Seen("a") {
		t.Fatal(err)
	}
}

func TestNullFileIsCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.json")
	if err := os.WriteFile(path, []byte("null"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, now); err == nil {
		t.Fatal("expected error")
	}
}

func TestRecordRejectsDuplicate(t *testing.T) {
	c, _ := Open(filepath.Join(t.TempDir(), "replay.json"), now)
	exp := time.Now().Add(time.Hour)
	if err := c.Record("a", exp); err != nil {
		t.Fatal(err)
	}
	if err := c.Record("a", exp); !errors.Is(err, ErrSeen) {
		t.Fatalf("got %v", err)
	}
}

func TestConcurrentRecordExactlyOnce(t *testing.T) {
	c, _ := Open(filepath.Join(t.TempDir(), "replay.json"), now)
	exp := time.Now().Add(time.Hour)
	const n = 16
	var wg sync.WaitGroup
	var ok, seen atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := c.Record("same", exp); {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrSeen):
				seen.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || seen.Load() != n-1 {
		t.Fatalf("ok=%d seen=%d", ok.Load(), seen.Load())
	}
}

func TestRecordPersistFailureLeavesCacheUnchanged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "replay.json")
	c, _ := Open(path, now)
	exp := time.Now().Add(time.Hour)
	if err := c.Record("old", exp); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := c.Record("new", exp); err == nil {
		t.Fatal("expected persist error")
	}
	if c.Seen("new") {
		t.Fatal("failed record must not be seen")
	}
	if !c.Seen("old") {
		t.Fatal("previous id must survive failed record")
	}
}

func TestFileModeAfterSecondWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.json")
	c, _ := Open(path, now)
	exp := time.Now().Add(time.Hour)
	for _, id := range []string{"a", "b"} {
		if err := c.Record(id, exp); err != nil {
			t.Fatal(err)
		}
		if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("mode: %v %v", st, err)
		}
	}
}

func TestRecordPrunesExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.json")
	c, _ := Open(path, now)
	if err := c.Record("stale", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := c.Record("fresh", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "stale") {
		t.Fatalf("not pruned: %s", b)
	}
}
