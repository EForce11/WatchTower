// Package verify loads trusted public keys and verifies signed commands.
package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeyClass is the trust class of a key.
type KeyClass int

// Key classes.
const (
	KeyAutomation KeyClass = iota + 1
	KeyAdmin
)

type entry struct {
	pub   ed25519.PublicKey
	class KeyClass
}

// Keyring maps key ids to public keys and their class.
type Keyring struct {
	keys map[string]entry
}

// KeyID returns the lowercase hex SHA-256 of the raw public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// ParsePublicKeyPEM parses a PKIX PEM-encoded Ed25519 public key.
func ParsePublicKeyPEM(b []byte) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block found")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T, want ed25519", k)
	}
	return pub, nil
}

func loadKeyFile(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-configured key path
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	pub, err := ParsePublicKeyPEM(b)
	if err != nil {
		return nil, fmt.Errorf("key %s: %w", path, err)
	}
	return pub, nil
}

// LoadKeyring loads the automation key file and every *.pub file in
// adminDir (non-recursive). A missing adminDir yields no admin keys.
func LoadKeyring(automationPEM, adminDir string) (*Keyring, error) {
	pub, err := loadKeyFile(automationPEM)
	if err != nil {
		return nil, err
	}
	k := &Keyring{keys: map[string]entry{KeyID(pub): {pub: pub, class: KeyAutomation}}}

	des, err := os.ReadDir(adminDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return k, nil
		}
		return nil, fmt.Errorf("read admin key dir %s: %w", adminDir, err)
	}
	for _, de := range des {
		if de.IsDir() || filepath.Ext(de.Name()) != ".pub" {
			continue
		}
		path := filepath.Join(adminDir, de.Name())
		ap, err := loadKeyFile(path)
		if err != nil {
			return nil, err
		}
		id := KeyID(ap)
		if _, dup := k.keys[id]; dup {
			return nil, fmt.Errorf("key %s duplicates an already loaded key", path)
		}
		k.keys[id] = entry{pub: ap, class: KeyAdmin}
	}
	return k, nil
}
