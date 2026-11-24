package synapsev1

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// MaxFrameBytes is the largest message body (inclusive) accepted in a frame.
const MaxFrameBytes = 65536

// ErrFrameTooLarge is returned when a frame body exceeds MaxFrameBytes.
var ErrFrameTooLarge = errors.New("synapse: frame exceeds maximum size")

// WriteFrame marshals m and writes it as a 4-byte big-endian length prefix
// followed by the body, in a single Write call. Nothing is written if the
// message is too large or fails to marshal.
func WriteFrame(w io.Writer, m proto.Message) error {
	body, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("synapse: marshal frame: %w", err)
	}
	if len(body) > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("synapse: write frame: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed frame into m. It returns io.EOF only
// when the stream ends cleanly before any header byte; a stream that ends
// mid-frame yields io.ErrUnexpectedEOF. The announced length is checked
// against MaxFrameBytes before any body allocation.
func ReadFrame(r io.Reader, m proto.Message) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err // io.EOF if nothing read, io.ErrUnexpectedEOF if partial
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	if err := proto.Unmarshal(body, m); err != nil {
		return fmt.Errorf("synapse: unmarshal frame: %w", err)
	}
	return nil
}
