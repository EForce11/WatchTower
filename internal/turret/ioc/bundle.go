// Package ioc loads the signed indicator-of-compromise bundle.
package ioc

import (
	"errors"
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"

	"github.com/EForce11/WatchTower/internal/turret/verify"
	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

// Set is a verified collection of malware SHA-256 hashes.
type Set struct {
	Version uint64
	hashes  map[[32]byte]struct{}
}

// Load reads and verifies a signed IOC bundle. The signature must come from
// the automation key. A missing file yields an empty Set.
func Load(path string, k *verify.Keyring) (*Set, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Set{hashes: map[[32]byte]struct{}{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ioc: read %s: %w", path, err)
	}
	var sb synapsev1.SignedIocBundle
	if err := proto.Unmarshal(raw, &sb); err != nil {
		return nil, fmt.Errorf("ioc: decode signed bundle: %w", err)
	}
	class, err := k.VerifyDetached(sb.GetPayload(), sb.GetSignature(), sb.GetKeyId())
	if err != nil {
		return nil, fmt.Errorf("ioc: verify bundle: %w", err)
	}
	if class != verify.KeyAutomation {
		return nil, errors.New("ioc: bundle must be signed by the automation key")
	}
	var b synapsev1.IocBundle
	if err := proto.Unmarshal(sb.GetPayload(), &b); err != nil {
		return nil, fmt.Errorf("ioc: decode bundle: %w", err)
	}
	s := &Set{Version: b.GetVersion(), hashes: make(map[[32]byte]struct{}, len(b.GetSha256()))}
	for i, h := range b.GetSha256() {
		if len(h) != 32 {
			return nil, fmt.Errorf("ioc: sha256 entry %d has %d bytes, want 32", i, len(h))
		}
		s.hashes[[32]byte(h)] = struct{}{}
	}
	return s, nil
}

// HasSHA256 reports whether h is a known-malicious hash.
func (s *Set) HasSHA256(h [32]byte) bool {
	if s == nil {
		return false
	}
	_, ok := s.hashes[h]
	return ok
}
