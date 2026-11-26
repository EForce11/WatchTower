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

// Cache maps command_id to its expiry.
type Cache struct {
	mu   sync.Mutex
	path string
	ids  map[string]int64
}

// Open loads the cache at path, dropping expired entries. A missing file is
// an empty cache; a corrupt file is an error (fail closed). If entries were
// dropped the file is rewritten.
func Open(path string, now time.Time) (*Cache, error) {
	c := &Cache{path: path, ids: map[string]int64{}}
	b, err := os.ReadFile(path) //nolint:gosec // caller-supplied state path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return nil, fmt.Errorf("read replay cache: %w", err)
	}
	var loaded map[string]int64
	if err := json.Unmarshal(b, &loaded); err != nil {
		return nil, fmt.Errorf("corrupt replay cache %s: %w", path, err)
	}
	pruned := false
	for id, exp := range loaded {
		if exp < now.Unix() {
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
	_, ok := c.ids[id]
	return ok
}

// Record stores id until expiresAt and persists the cache before returning.
func (c *Cache) Record(id string, expiresAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ids[id] = expiresAt.Unix()
	if err := c.persist(); err != nil {
		delete(c.ids, id)
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
	tmp := c.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // caller-supplied state path
	if err != nil {
		return fmt.Errorf("create replay temp: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("write replay temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync replay temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close replay temp: %w", err)
	}
	if err := os.Rename(tmp, c.path); err != nil {
		return fmt.Errorf("rename replay cache: %w", err)
	}
	if d, err := os.Open(filepath.Dir(c.path)); err == nil { //nolint:gosec // state dir
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
