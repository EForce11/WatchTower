package verify

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

// Verification errors.
var (
	ErrUnknownKey        = errors.New("unknown key id")
	ErrBadSignature      = errors.New("bad signature")
	ErrUnsupportedScheme = errors.New("unsupported signature scheme")
	ErrMalformedPayload  = errors.New("malformed command payload")
	ErrWrongAgent        = errors.New("command addressed to another agent")
	ErrNotYetValid       = errors.New("command not yet valid")
	ErrExpired           = errors.New("command expired")
	ErrLifetime          = errors.New("command lifetime exceeds limit")
)

const (
	clockSkew        = 30 * time.Second
	automationMaxTTL = 120 * time.Second
	adminMaxTTL      = 3600 * time.Second
)

// Verified is a command that passed all checks.
type Verified struct {
	Payload *synapsev1.CommandPayload
	Class   KeyClass
	KeyID   string
}

// VerifyDetached checks an Ed25519 signature over payload with the key
// named keyID and returns the key's class.
func (k *Keyring) VerifyDetached(payload, sig []byte, keyID string) (KeyClass, error) {
	e, ok := k.keys[keyID]
	if !ok {
		return 0, ErrUnknownKey
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(e.pub, payload, sig) {
		return 0, ErrBadSignature
	}
	return e.class, nil
}

// Verify checks scheme, key, signature, agent, validity window and lifetime
// in that order.
func (k *Keyring) Verify(sc *synapsev1.SignedCommand, agentID string, now time.Time) (Verified, error) {
	if sc == nil {
		return Verified{}, fmt.Errorf("nil signed command: %w", ErrBadSignature)
	}
	if sc.GetScheme() != synapsev1.SignatureScheme_SIGNATURE_SCHEME_ED25519 {
		return Verified{}, ErrUnsupportedScheme
	}
	class, err := k.VerifyDetached(sc.GetPayload(), sc.GetSignature(), sc.GetKeyId())
	if err != nil {
		return Verified{}, err
	}
	p := &synapsev1.CommandPayload{}
	if err := proto.Unmarshal(sc.GetPayload(), p); err != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrMalformedPayload, err)
	}
	if p.GetAgentId() != agentID {
		return Verified{}, ErrWrongAgent
	}
	issued := time.Unix(p.GetIssuedAt(), 0)
	expires := time.Unix(p.GetExpiresAt(), 0)
	if now.Before(issued.Add(-clockSkew)) {
		return Verified{}, ErrNotYetValid
	}
	if now.After(expires) {
		return Verified{}, ErrExpired
	}
	limit := automationMaxTTL
	if class == KeyAdmin {
		limit = adminMaxTTL
	}
	if life := expires.Sub(issued); life < 0 || life > limit {
		return Verified{}, ErrLifetime
	}
	return Verified{Payload: p, Class: class, KeyID: sc.GetKeyId()}, nil
}
