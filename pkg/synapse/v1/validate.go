package synapsev1

import (
	"errors"
	"fmt"
)

// Event size limits, enforced identically by every producer and the Core ingest.
// All lengths are in bytes, not runes.
const (
	MaxAttrs           = 16
	MaxAttrValueBytes  = 256
	MaxRawExcerptBytes = 512
)

var (
	ErrMissingField      = errors.New("missing required field")
	ErrAttrsTooMany      = errors.New("too many attrs")
	ErrAttrValueTooLong  = errors.New("attr value too long")
	ErrRawExcerptTooLong = errors.New("raw_excerpt too long")
)

// ValidateEvent checks required fields and size limits. Returned errors wrap
// the exported sentinels; use errors.Is.
func ValidateEvent(e *Event) error {
	if e == nil {
		return fmt.Errorf("%w: event", ErrMissingField)
	}
	if e.GetEventId() == "" {
		return fmt.Errorf("%w: event_id", ErrMissingField)
	}
	if e.GetTime() == nil {
		return fmt.Errorf("%w: time", ErrMissingField)
	}
	if e.GetAgentId() == "" {
		return fmt.Errorf("%w: agent_id", ErrMissingField)
	}
	if e.GetClass() == EventClass_EVENT_CLASS_UNSPECIFIED {
		return fmt.Errorf("%w: class", ErrMissingField)
	}
	if n := len(e.GetAttrs()); n > MaxAttrs {
		return fmt.Errorf("%w: %d > %d", ErrAttrsTooMany, n, MaxAttrs)
	}
	for k, v := range e.GetAttrs() {
		if len(v) > MaxAttrValueBytes {
			return fmt.Errorf("%w: attrs[%q] is %d bytes > %d", ErrAttrValueTooLong, k, len(v), MaxAttrValueBytes)
		}
	}
	if n := len(e.GetRawExcerpt()); n > MaxRawExcerptBytes {
		return fmt.Errorf("%w: %d bytes > %d", ErrRawExcerptTooLong, n, MaxRawExcerptBytes)
	}
	return nil
}
