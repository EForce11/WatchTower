package synapsev1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestFrameRoundTrip(t *testing.T) {
	in := &TurretRequest{Kind: &TurretRequest_Reflex{Reflex: &ReflexRequest{
		RequestId: "req-1",
		Target:    "10.0.0.5",
		Pid:       4242,
		ExePath:   "/tmp/x",
		RuleId:    "rule-1",
	}}}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	out := &TurretRequest{}
	if err := ReadFrame(&buf, out); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !proto.Equal(in, out) {
		t.Fatalf("round trip mismatch: %v != %v", in, out)
	}
}

func TestReadFrameRejectsOversizedLength(t *testing.T) {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, MaxFrameBytes+1)
	err := ReadFrame(bytes.NewReader(hdr), &TurretRequest{})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrameAcceptsExactLimitHeader(t *testing.T) {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, MaxFrameBytes)
	err := ReadFrame(bytes.NewReader(hdr), &TurretRequest{})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadFrameEmptyBodyIsValid(t *testing.T) {
	out := &TurretRequest{}
	if err := ReadFrame(bytes.NewReader(make([]byte, 4)), out); err != nil {
		t.Fatalf("got %v", err)
	}
}

func TestReadFrameTruncatedBody(t *testing.T) {
	data := []byte{0, 0, 0, 10, 1, 2, 3}
	err := ReadFrame(bytes.NewReader(data), &TurretRequest{})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadFrameTruncatedHeader(t *testing.T) {
	err := ReadFrame(bytes.NewReader([]byte{0, 0}), &TurretRequest{})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestWriteFrameRejectsOversizedMessage(t *testing.T) {
	m := &TurretRequest{Kind: &TurretRequest_Signed{Signed: &SignedCommand{Payload: make([]byte, 70000)}}}
	var buf bytes.Buffer
	err := WriteFrame(&buf, m)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("wrote %d bytes, want 0", buf.Len())
	}
}

func TestReadFrameEmptyStream(t *testing.T) {
	err := ReadFrame(bytes.NewReader(nil), &TurretRequest{})
	if err != io.EOF {
		t.Fatalf("got %v, want io.EOF", err)
	}
}
