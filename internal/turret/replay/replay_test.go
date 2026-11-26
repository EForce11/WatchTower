package replay

import (
	"os"
	"path/filepath"
	"strconv"
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
	if err := os.WriteFile(path+".tmp", []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Record("a", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("tmp should be consumed by rename: %v", err)
	}
	c2, err := Open(path, now)
	if err != nil || !c2.Seen("a") {
		t.Fatal(err)
	}
}
