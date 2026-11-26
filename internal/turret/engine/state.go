package engine

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/EForce11/WatchTower/internal/turret/nft"
)

// BanRecord is one persisted ban. ExpiresAt is Unix seconds; 0 means
// permanent.
type BanRecord struct {
	Prefix    string `json:"prefix"`
	Kind      string `json:"kind"`
	ExpiresAt int64  `json:"expires_at"`
}

type recKey struct {
	prefix netip.Prefix
	kind   nft.Kind
}

// banStore is the in-memory view of <state_dir>/bans.json. It is not
// internally synchronized; the Engine serializes access.
type banStore struct {
	path string
	recs map[recKey]int64
}

var kindByName = map[string]nft.Kind{
	nft.KindBan.String():       nft.KindBan,
	nft.KindPerm.String():      nft.KindPerm,
	nft.KindRateLimit.String(): nft.KindRateLimit,
}

// loadStore reads the state file, dropping records that expired before now.
// A missing file is an empty store; a corrupt one is an error (fail closed).
// If records were dropped the file is rewritten.
func loadStore(path string, now time.Time) (*banStore, error) {
	s := &banStore{path: path, recs: map[recKey]int64{}}
	b, err := os.ReadFile(path) //nolint:gosec // operator-configured state path
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read ban state: %w", err)
	}
	var loaded []BanRecord
	if err := json.Unmarshal(b, &loaded); err != nil || loaded == nil {
		return nil, fmt.Errorf("corrupt ban state %s: %v", path, err)
	}
	pruned := false
	for _, r := range loaded {
		k, err := parseRecord(r)
		if err != nil {
			return nil, fmt.Errorf("corrupt ban state %s: %w", path, err)
		}
		if r.ExpiresAt != 0 && r.ExpiresAt <= now.Unix() {
			pruned = true
			continue
		}
		s.put(k, r.ExpiresAt)
	}
	if pruned {
		if err := s.persist(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func parseRecord(r BanRecord) (recKey, error) {
	p, err := netip.ParsePrefix(r.Prefix)
	if err != nil || p.Masked() != p {
		return recKey{}, fmt.Errorf("bad prefix %q", r.Prefix)
	}
	k, ok := kindByName[r.Kind]
	if !ok {
		return recKey{}, fmt.Errorf("bad kind %q", r.Kind)
	}
	if k == nft.KindRateLimit && p.Bits() != p.Addr().BitLen() {
		return recKey{}, fmt.Errorf("ratelimit record %q is not a single address", r.Prefix)
	}
	return recKey{p, k}, nil
}

// put stores a record, keeping the later expiry for the same prefix and kind
// (mirrors the firewall's never-shorten rule). Permanent (0) only occurs for
// KindPerm.
func (s *banStore) put(k recKey, exp int64) {
	if k.kind == nft.KindPerm {
		s.recs[k] = 0
		return
	}
	if old, ok := s.recs[k]; ok && old > exp {
		return
	}
	s.recs[k] = exp
}

func (s *banStore) hasPerm(p netip.Prefix) bool {
	_, ok := s.recs[recKey{p, nft.KindPerm}]
	return ok
}

// deletePrefix removes every record with exactly this prefix.
func (s *banStore) deletePrefix(p netip.Prefix) {
	for k := range s.recs {
		if k.prefix == p {
			delete(s.recs, k)
		}
	}
}

// sorted returns the records in a deterministic order.
func (s *banStore) sorted() []BanRecord {
	out := make([]BanRecord, 0, len(s.recs))
	for k, exp := range s.recs {
		out = append(out, BanRecord{Prefix: k.prefix.String(), Kind: k.kind.String(), ExpiresAt: exp})
	}
	slices.SortFunc(out, func(a, b BanRecord) int {
		return cmp.Or(cmp.Compare(a.Prefix, b.Prefix), cmp.Compare(a.Kind, b.Kind))
	})
	return out
}

// persist writes the store atomically (temp file, fsync, rename).
func (s *banStore) persist() error {
	b, err := json.Marshal(s.sorted())
	if err != nil {
		return fmt.Errorf("encode ban state: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create ban state temp: %w", err)
	}
	tmp := f.Name()
	fail := func(op string, err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("%s ban state temp: %w", op, err)
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
		return fmt.Errorf("close ban state temp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename ban state: %w", err)
	}
	if d, err := os.Open(filepath.Dir(s.path)); err == nil { //nolint:gosec // state dir
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
