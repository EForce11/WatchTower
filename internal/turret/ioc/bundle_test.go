package ioc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/EForce11/WatchTower/internal/turret/verify"
	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

type fx struct {
	ring            *verify.Keyring
	autoPub, admPub ed25519.PublicKey
	autoPriv        ed25519.PrivateKey
	admPriv         ed25519.PrivateKey
	dir             string
}

func pemOf(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func newFx(t *testing.T) *fx {
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
	ring, err := verify.LoadKeyring(autoPath, adminDir)
	if err != nil {
		t.Fatal(err)
	}
	return &fx{ring: ring, autoPub: ap, autoPriv: apriv, admPub: dp, admPriv: dpriv, dir: dir}
}

func (f *fx) write(t *testing.T, hashes [][]byte, priv ed25519.PrivateKey, pub ed25519.PublicKey, tamper bool) string {
	t.Helper()
	payload, err := proto.Marshal(&synapsev1.IocBundle{Version: 7, IssuedAt: 1, Sha256: hashes})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payload)
	if tamper {
		payload = append(payload, 0x00)
	}
	raw, err := proto.Marshal(&synapsev1.SignedIocBundle{Payload: payload, Signature: sig, KeyId: verify.KeyID(pub)})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(f.dir, "ioc.bin")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAutomationSigned(t *testing.T) {
	f := newFx(t)
	h := sha256.Sum256([]byte("evil"))
	s, err := Load(f.write(t, [][]byte{h[:]}, f.autoPriv, f.autoPub, false), f.ring)
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasSHA256(h) || s.Version != 7 {
		t.Fatalf("set = %+v", s)
	}
	if s.HasSHA256(sha256.Sum256([]byte("good"))) {
		t.Fatal("unexpected hit")
	}
}

func TestLoadAdminSignedRejected(t *testing.T) {
	f := newFx(t)
	h := sha256.Sum256([]byte("evil"))
	if _, err := Load(f.write(t, [][]byte{h[:]}, f.admPriv, f.admPub, false), f.ring); err == nil {
		t.Fatal("admin-signed bundle accepted")
	}
}

func TestLoadTamperedRejected(t *testing.T) {
	f := newFx(t)
	h := sha256.Sum256([]byte("evil"))
	if _, err := Load(f.write(t, [][]byte{h[:]}, f.autoPriv, f.autoPub, true), f.ring); err == nil {
		t.Fatal("tampered bundle accepted")
	}
}

func TestLoadBadHashLength(t *testing.T) {
	f := newFx(t)
	if _, err := Load(f.write(t, [][]byte{{1, 2, 3}}, f.autoPriv, f.autoPub, false), f.ring); err == nil {
		t.Fatal("short hash accepted")
	}
}

func TestLoadMissingFileEmptySet(t *testing.T) {
	f := newFx(t)
	s, err := Load(filepath.Join(f.dir, "nope"), f.ring)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil || s.HasSHA256([32]byte{}) {
		t.Fatalf("set = %+v", s)
	}
}

func (f *fx) writeRaw(t *testing.T, raw []byte) string {
	t.Helper()
	p := filepath.Join(f.dir, "raw.bin")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadGarbageOuter(t *testing.T) {
	f := newFx(t)
	if _, err := Load(f.writeRaw(t, []byte{0xff, 0xff, 0xff, 0xff}), f.ring); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestLoadUnknownKey(t *testing.T) {
	f := newFx(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := sha256.Sum256([]byte("evil"))
	_, err := Load(f.write(t, [][]byte{h[:]}, priv, pub, false), f.ring)
	if !errors.Is(err, verify.ErrUnknownKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadTamperedErrorKind(t *testing.T) {
	f := newFx(t)
	h := sha256.Sum256([]byte("evil"))
	_, err := Load(f.write(t, [][]byte{h[:]}, f.autoPriv, f.autoPub, true), f.ring)
	if !errors.Is(err, verify.ErrBadSignature) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadValidSignatureUndecodablePayload(t *testing.T) {
	f := newFx(t)
	payload := []byte{0xff, 0xff, 0xff}
	raw, err := proto.Marshal(&synapsev1.SignedIocBundle{
		Payload: payload, Signature: ed25519.Sign(f.autoPriv, payload), KeyId: verify.KeyID(f.autoPub),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f.writeRaw(t, raw), f.ring); err == nil {
		t.Fatal("undecodable payload accepted")
	}
}
