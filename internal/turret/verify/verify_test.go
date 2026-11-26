package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

var t0 = time.Unix(1_800_000_000, 0)

func pemOf(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

type fixture struct {
	ring            *Keyring
	autoPub, admPub ed25519.PublicKey
	autoPriv        ed25519.PrivateKey
	admPriv         ed25519.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ap, apriv, _ := ed25519.GenerateKey(rand.Reader)
	dp, dpriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	autoPath := filepath.Join(dir, "automation.pub")
	if err := os.WriteFile(autoPath, pemOf(t, ap), 0o600); err != nil {
		t.Fatal(err)
	}
	adminDir := filepath.Join(dir, "admin")
	if err := os.Mkdir(adminDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(adminDir, "alice.pub"), pemOf(t, dp), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(adminDir, "README.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	ring, err := LoadKeyring(autoPath, adminDir)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{ring: ring, autoPub: ap, autoPriv: apriv, admPub: dp, admPriv: dpriv}
}

func sign(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, p *synapsev1.CommandPayload) *synapsev1.SignedCommand {
	t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return &synapsev1.SignedCommand{
		Payload:   b,
		Signature: ed25519.Sign(priv, b),
		KeyId:     KeyID(pub),
		Scheme:    synapsev1.SignatureScheme_SIGNATURE_SCHEME_ED25519,
	}
}

func payload(lifetime int64) *synapsev1.CommandPayload {
	return &synapsev1.CommandPayload{
		CommandId: "c1",
		AgentId:   "agent-1",
		IssuedAt:  t0.Unix(),
		ExpiresAt: t0.Unix() + lifetime,
	}
}

func TestVerifyClasses(t *testing.T) {
	f := newFixture(t)
	v, err := f.ring.Verify(sign(t, f.autoPriv, f.autoPub, payload(60)), "agent-1", t0)
	if err != nil || v.Class != KeyAutomation || v.KeyID != KeyID(f.autoPub) || v.Payload.CommandId != "c1" {
		t.Fatalf("automation: %+v %v", v, err)
	}
	v, err = f.ring.Verify(sign(t, f.admPriv, f.admPub, payload(60)), "agent-1", t0)
	if err != nil || v.Class != KeyAdmin {
		t.Fatalf("admin: %+v %v", v, err)
	}
}

func TestVerifyErrors(t *testing.T) {
	f := newFixture(t)
	good := func() *synapsev1.SignedCommand { return sign(t, f.autoPriv, f.autoPub, payload(60)) }

	t.Run("unknown key", func(t *testing.T) {
		sc := good()
		sc.KeyId = "deadbeef"
		if _, err := f.ring.Verify(sc, "agent-1", t0); !errors.Is(err, ErrUnknownKey) {
			t.Fatal(err)
		}
	})
	t.Run("flipped byte", func(t *testing.T) {
		sc := good()
		sc.Payload[0] ^= 0xff
		if _, err := f.ring.Verify(sc, "agent-1", t0); !errors.Is(err, ErrBadSignature) {
			t.Fatal(err)
		}
	})
	t.Run("webauthn", func(t *testing.T) {
		sc := good()
		sc.Scheme = synapsev1.SignatureScheme_SIGNATURE_SCHEME_WEBAUTHN_ES256
		if _, err := f.ring.Verify(sc, "agent-1", t0); !errors.Is(err, ErrUnsupportedScheme) {
			t.Fatal(err)
		}
	})
	t.Run("wrong agent", func(t *testing.T) {
		if _, err := f.ring.Verify(good(), "agent-2", t0); !errors.Is(err, ErrWrongAgent) {
			t.Fatal(err)
		}
	})
}

func TestVerifyWindowAndLifetime(t *testing.T) {
	f := newFixture(t)
	good := func() *synapsev1.SignedCommand { return sign(t, f.autoPriv, f.autoPub, payload(60)) }

	t.Run("not yet valid", func(t *testing.T) {
		if _, err := f.ring.Verify(good(), "agent-1", t0.Add(-31*time.Second)); !errors.Is(err, ErrNotYetValid) {
			t.Fatal(err)
		}
		if _, err := f.ring.Verify(good(), "agent-1", t0.Add(-30*time.Second)); err != nil {
			t.Fatalf("boundary -30s: %v", err)
		}
		if _, err := f.ring.Verify(good(), "agent-1", t0.Add(-29*time.Second)); err != nil {
			t.Fatalf("-29s: %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		if _, err := f.ring.Verify(good(), "agent-1", t0.Add(61*time.Second)); !errors.Is(err, ErrExpired) {
			t.Fatal(err)
		}
		if _, err := f.ring.Verify(good(), "agent-1", t0.Add(60*time.Second)); err != nil {
			t.Fatalf("boundary expiry: %v", err)
		}
	})
	t.Run("automation lifetime", func(t *testing.T) {
		if _, err := f.ring.Verify(sign(t, f.autoPriv, f.autoPub, payload(121)), "agent-1", t0); !errors.Is(err, ErrLifetime) {
			t.Fatal(err)
		}
		if _, err := f.ring.Verify(sign(t, f.autoPriv, f.autoPub, payload(120)), "agent-1", t0); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("admin lifetime", func(t *testing.T) {
		if _, err := f.ring.Verify(sign(t, f.admPriv, f.admPub, payload(3601)), "agent-1", t0); !errors.Is(err, ErrLifetime) {
			t.Fatal(err)
		}
		if _, err := f.ring.Verify(sign(t, f.admPriv, f.admPub, payload(3600)), "agent-1", t0); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("negative lifetime", func(t *testing.T) {
		p := payload(-5)
		if _, err := f.ring.Verify(sign(t, f.autoPriv, f.autoPub, p), "agent-1", t0.Add(-5*time.Second)); !errors.Is(err, ErrLifetime) {
			t.Fatal(err)
		}
	})
	t.Run("garbage payload", func(t *testing.T) {
		b := []byte{0xff, 0xff, 0xff}
		sc := &synapsev1.SignedCommand{Payload: b, Signature: ed25519.Sign(f.autoPriv, b), KeyId: KeyID(f.autoPub), Scheme: synapsev1.SignatureScheme_SIGNATURE_SCHEME_ED25519}
		if _, err := f.ring.Verify(sc, "agent-1", t0); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestVerifyNilAndEmpty(t *testing.T) {
	f := newFixture(t)
	if _, err := f.ring.Verify(nil, "agent-1", t0); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("nil: %v", err)
	}
	empty := &synapsev1.SignedCommand{Scheme: synapsev1.SignatureScheme_SIGNATURE_SCHEME_ED25519, KeyId: KeyID(f.autoPub)}
	if _, err := f.ring.Verify(empty, "agent-1", t0); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := f.ring.Verify(&synapsev1.SignedCommand{}, "agent-1", t0); err == nil {
		t.Fatal("zero value must error")
	}
}

func TestVerifyDetached(t *testing.T) {
	f := newFixture(t)
	blob := []byte("ioc bundle")
	sig := ed25519.Sign(f.autoPriv, blob)
	class, err := f.ring.VerifyDetached(blob, sig, KeyID(f.autoPub))
	if err != nil || class != KeyAutomation {
		t.Fatalf("%v %v", class, err)
	}
	if _, err := f.ring.VerifyDetached([]byte("tampered"), sig, KeyID(f.autoPub)); !errors.Is(err, ErrBadSignature) {
		t.Fatal(err)
	}
	if _, err := f.ring.VerifyDetached(blob, sig, "nope"); !errors.Is(err, ErrUnknownKey) {
		t.Fatal(err)
	}
	if _, err := f.ring.VerifyDetached(blob, nil, KeyID(f.autoPub)); !errors.Is(err, ErrBadSignature) {
		t.Fatal(err)
	}
}

func TestLoadKeyring(t *testing.T) {
	ap, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	autoPath := filepath.Join(dir, "a.pub")
	if err := os.WriteFile(autoPath, pemOf(t, ap), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("missing admin dir", func(t *testing.T) {
		if _, err := LoadKeyring(autoPath, filepath.Join(dir, "nope")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("same key in both classes", func(t *testing.T) {
		ad := t.TempDir()
		if err := os.WriteFile(filepath.Join(ad, "dup.pub"), pemOf(t, ap), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeyring(autoPath, ad); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("malformed admin key names file", func(t *testing.T) {
		ad := t.TempDir()
		if err := os.WriteFile(filepath.Join(ad, "broken.pub"), []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadKeyring(autoPath, ad)
		if err == nil || !regexp.MustCompile(`broken\.pub`).MatchString(err.Error()) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing automation key", func(t *testing.T) {
		if _, err := LoadKeyring(filepath.Join(dir, "absent.pub"), ""); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestParsePublicKeyPEM(t *testing.T) {
	ap, _, _ := ed25519.GenerateKey(rand.Reader)
	got, err := ParsePublicKeyPEM(pemOf(t, ap))
	if err != nil || !got.Equal(ap) {
		t.Fatalf("%v", err)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	if _, err := ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err == nil {
		t.Fatal("RSA must be rejected")
	}
	if _, err := ParsePublicKeyPEM([]byte("garbage")); err == nil {
		t.Fatal("garbage must be rejected")
	}
}

func TestKeyID(t *testing.T) {
	ap, _, _ := ed25519.GenerateKey(rand.Reader)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(KeyID(ap)) {
		t.Fatal(KeyID(ap))
	}
}
