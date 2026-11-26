package safety

import (
	"testing"
	"time"

	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

func TestCheckTable(t *testing.T) {
	const (
		R = OriginReflex
		A = OriginAutomation
		M = OriginAdmin
	)
	// allowed[action] = {reflex, automation, admin} per architecture §3.4.1.
	table := []struct {
		a       synapsev1.Action
		allowed [3]bool
	}{
		{synapsev1.Action_ACTION_RATE_LIMIT, [3]bool{true, true, true}},
		{synapsev1.Action_ACTION_BAN_TEMP, [3]bool{true, true, true}},
		{synapsev1.Action_ACTION_KILL_TEMP_MALWARE, [3]bool{true, true, true}},
		{synapsev1.Action_ACTION_UNBAN, [3]bool{false, true, true}},
		{synapsev1.Action_ACTION_BAN_PERM, [3]bool{false, false, true}},
		{synapsev1.Action_ACTION_KILL_PROCESS, [3]bool{false, false, true}},
		{synapsev1.Action_ACTION_ISOLATE_HOST, [3]bool{false, false, true}},
		{synapsev1.Action_ACTION_RELEASE_HOST, [3]bool{false, false, true}},
	}
	for _, row := range table {
		for i, o := range []Origin{R, A, M} {
			d := Check(o, row.a, 10*time.Minute)
			if d.Allowed != row.allowed[i] {
				t.Errorf("%s origin %d: allowed=%v want %v (%s)", row.a, o, d.Allowed, row.allowed[i], d.Reason)
			}
			if !d.Allowed && (d.Result != synapsev1.TurretResult_TURRET_RESULT_REFUSED_SAFETY || d.Reason == "") {
				t.Errorf("%s origin %d: refusal needs REFUSED_SAFETY and a reason, got %+v", row.a, o, d)
			}
		}
	}
}

func TestCheckTTL(t *testing.T) {
	const day = 24 * time.Hour
	tests := []struct {
		name string
		o    Origin
		a    synapsev1.Action
		ttl  time.Duration
		ok   bool
	}{
		{"reflex ban 900s", OriginReflex, synapsev1.Action_ACTION_BAN_TEMP, 900 * time.Second, true},
		{"reflex ban 901s", OriginReflex, synapsev1.Action_ACTION_BAN_TEMP, 901 * time.Second, false},
		{"automation ban 7d", OriginAutomation, synapsev1.Action_ACTION_BAN_TEMP, 7 * day, true},
		{"automation ban 604801s", OriginAutomation, synapsev1.Action_ACTION_BAN_TEMP, 604801 * time.Second, false},
		{"admin ban 30d", OriginAdmin, synapsev1.Action_ACTION_BAN_TEMP, 30 * day, true},
		{"reflex ban ttl 0", OriginReflex, synapsev1.Action_ACTION_BAN_TEMP, 0, false},
		{"admin ban ttl 0", OriginAdmin, synapsev1.Action_ACTION_BAN_TEMP, 0, false},
		{"admin ban negative", OriginAdmin, synapsev1.Action_ACTION_BAN_TEMP, -time.Second, false},
		{"reflex ratelimit 15m", OriginReflex, synapsev1.Action_ACTION_RATE_LIMIT, 15 * time.Minute, true},
		{"reflex ratelimit 901s", OriginReflex, synapsev1.Action_ACTION_RATE_LIMIT, 901 * time.Second, false},
		{"automation ratelimit 901s", OriginAutomation, synapsev1.Action_ACTION_RATE_LIMIT, 901 * time.Second, false},
		{"admin ratelimit 901s", OriginAdmin, synapsev1.Action_ACTION_RATE_LIMIT, 901 * time.Second, false},
		{"admin ratelimit ttl 0", OriginAdmin, synapsev1.Action_ACTION_RATE_LIMIT, 0, false},
		{"unban ignores ttl", OriginAutomation, synapsev1.Action_ACTION_UNBAN, 0, true},
		{"ban perm ignores ttl", OriginAdmin, synapsev1.Action_ACTION_BAN_PERM, 0, true},
		{"kill ignores ttl", OriginReflex, synapsev1.Action_ACTION_KILL_TEMP_MALWARE, 0, true},
		{"unspecified reflex", OriginReflex, synapsev1.Action_ACTION_UNSPECIFIED, time.Minute, false},
		{"unspecified admin", OriginAdmin, synapsev1.Action_ACTION_UNSPECIFIED, time.Minute, false},
		{"unknown origin", Origin(0), synapsev1.Action_ACTION_BAN_TEMP, time.Minute, false},
	}
	for _, tc := range tests {
		d := Check(tc.o, tc.a, tc.ttl)
		if d.Allowed != tc.ok {
			t.Errorf("%s: allowed=%v want %v (%s)", tc.name, d.Allowed, tc.ok, d.Reason)
		}
		if !d.Allowed && d.Result != synapsev1.TurretResult_TURRET_RESULT_REFUSED_SAFETY {
			t.Errorf("%s: result %v", tc.name, d.Result)
		}
	}
}
