// Package replay keeps a persistent cache of seen command ids.
package replay

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrSeen is returned by Record when the id is already present.
var ErrSeen = errors.New("command id already seen")

// Cache maps command_id to its expiry.
type Cache struct {
	mu   sync.Mutex
	path string
	ids  map[string]int64
	now  func() time.Time
}

// Open loads the cache at path using clock (nil means time.Now), dropping expired entries. A missing file is
// an empty cache; a corrupt file is an error (fail closed). If entries were
// dropped the file is rewritten.
func Open(path string, clock func() time.Time) (*Cache, error) {
	if clock == nil {
		clock = time.Now
	}
	c := &Cache{path: path, ids: map[string]int64{}, now: clock}
	nowUnix := clock().Unix()
	b, err := os.ReadFile(path) //nolint:gosec // caller-supplied state path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return nil, fmt.Errorf("read replay cache: %w", err)
	}
	var loaded map[string]int64
	if err := json.Unmarshal(b, &loaded); err != nil || loaded == nil {
		return nil, fmt.Errorf("corrupt replay cache %s: %v", path, err)
	}
	pruned := false
	for id, exp := range loaded {
		if exp < nowUnix {
			pruned = true
			continue
		}
		c.ids[id] = exp
	}
	if pruned {
		if err := c.persist(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Seen reports whether id has been recorded and not yet pruned.
func (c *Cache) Seen(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.ids[id]
	return ok && exp >= c.now().Unix()
}

// Record atomically checks and stores id until expiresAt and persists the
// cache before returning. It returns ErrSeen if id is already present and not
// expired. Expired entries are pruned. On a persist failure the cache is left
// as it was.
func (c *Cache) Record(id string, expiresAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	nowUnix := c.now().Unix()
	if exp, ok := c.ids[id]; ok && exp >= nowUnix {
		return ErrSeen
	}
	prev := make(map[string]int64, len(c.ids))
	for k, v := range c.ids {
		prev[k] = v
		if v < nowUnix {
			delete(c.ids, k)
		}
	}
	c.ids[id] = expiresAt.Unix()
	if err := c.persist(); err != nil {
		c.ids = prev
		return err
	}
	return nil
}

// persist writes the cache atomically; the caller holds c.mu (or has
// exclusive access).
func (c *Cache) persist() error {
	b, err := json.Marshal(c.ids)
	if err != nil {
		return fmt.Errorf("encode replay cache: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(c.path), filepath.Base(c.path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create replay temp: %w", err)
	}
	tmp := f.Name()
	fail := func(op string, err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("%s replay temp: %w", op, err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fail("chmod", err)
	}
	if _, err := f.Write(b); err != nil {
		return fail("write", err)
	}
	if err := f.Sync(); err != nil {
		return fail("sync", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close replay temp: %w", err)
	}
	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename replay cache: %w", err)
	}
	if d, err := os.Open(filepath.Dir(c.path)); err == nil { //nolint:gosec // state dir
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
