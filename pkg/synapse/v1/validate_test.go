package synapsev1_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func validEvent() *synapsev1.Event {
	return &synapsev1.Event{
		EventId:  "evt-1",
		Time:     timestamppb.New(time.Unix(1700000000, 0)),
		AgentId:  "agent-1",
		Class:    synapsev1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Severity: synapsev1.Severity_SEVERITY_LOW,
	}
}

func attrs(n int) map[string]string {
	m := make(map[string]string, n)
	for i := 0; i < n; i++ {
		m["k"+strconv.Itoa(i)] = "v"
	}
	return m
}

func TestValidateEvent(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(e *synapsev1.Event)
		want   error
	}{
		{"valid minimal", func(e *synapsev1.Event) {}, nil},
		{"empty event_id", func(e *synapsev1.Event) { e.EventId = "" }, synapsev1.ErrMissingField},
		{"nil time", func(e *synapsev1.Event) { e.Time = nil }, synapsev1.ErrMissingField},
		{"empty agent_id", func(e *synapsev1.Event) { e.AgentId = "" }, synapsev1.ErrMissingField},
		{"unspecified class", func(e *synapsev1.Event) { e.Class = synapsev1.EventClass_EVENT_CLASS_UNSPECIFIED }, synapsev1.ErrMissingField},
		{"17 attrs", func(e *synapsev1.Event) { e.Attrs = attrs(17) }, synapsev1.ErrAttrsTooMany},
		{"16 attrs", func(e *synapsev1.Event) { e.Attrs = attrs(16) }, nil},
		{"attr value 257 bytes", func(e *synapsev1.Event) { e.Attrs = map[string]string{"k": strings.Repeat("a", 257)} }, synapsev1.ErrAttrValueTooLong},
		{"attr value 256 bytes", func(e *synapsev1.Event) { e.Attrs = map[string]string{"k": strings.Repeat("a", 256)} }, nil},
		{"attr value 129 two-byte runes", func(e *synapsev1.Event) { e.Attrs = map[string]string{"k": strings.Repeat("é", 129)} }, synapsev1.ErrAttrValueTooLong},
		{"raw_excerpt 513 bytes", func(e *synapsev1.Event) { e.RawExcerpt = strings.Repeat("a", 513) }, synapsev1.ErrRawExcerptTooLong},
		{"raw_excerpt 512 bytes", func(e *synapsev1.Event) { e.RawExcerpt = strings.Repeat("a", 512) }, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := validEvent()
			tc.mutate(e)
			err := synapsev1.ValidateEvent(e)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateEventNil(t *testing.T) {
	if err := synapsev1.ValidateEvent(nil); !errors.Is(err, synapsev1.ErrMissingField) {
		t.Fatalf("want ErrMissingField, got %v", err)
	}
}
