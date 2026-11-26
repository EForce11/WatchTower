package safety

import (
	"fmt"
	"time"

	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

// TTL limits from the safety policy.
const (
	maxRateLimitTTL  = 15 * time.Minute
	maxReflexBanTTL  = 900 * time.Second
	maxAutomationTTL = 7 * 24 * time.Hour
)

// Decision is the outcome of a policy check.
type Decision struct {
	Allowed bool
	Result  synapsev1.TurretResult
	Reason  string
}

func refuse(format string, args ...any) Decision {
	return Decision{Result: synapsev1.TurretResult_TURRET_RESULT_REFUSED_SAFETY, Reason: fmt.Sprintf(format, args...)}
}

// Check applies the origin x action table and the TTL rules. ttl is only
// considered for RATE_LIMIT and BAN_TEMP.
func Check(o Origin, a synapsev1.Action, ttl time.Duration) Decision {
	if !validOrigin(o) {
		return refuse("rule unknown-origin")
	}
	switch a {
	case synapsev1.Action_ACTION_RATE_LIMIT:
		if ttl <= 0 || ttl > maxRateLimitTTL {
			return refuse("rule rate-limit-ttl: ttl %s outside (0, 15m]", ttl)
		}
		return Decision{Allowed: true}
	case synapsev1.Action_ACTION_BAN_TEMP:
		if ttl <= 0 {
			return refuse("rule ban-temp-ttl: ttl must be positive")
		}
		switch o {
		case OriginReflex:
			if ttl > maxReflexBanTTL {
				return refuse("rule reflex-ban-ttl: ttl %s exceeds 900s", ttl)
			}
		case OriginAutomation:
			if ttl > maxAutomationTTL {
				return refuse("rule automation-ban-ttl: ttl %s exceeds 7d", ttl)
			}
		}
		return Decision{Allowed: true}
	case synapsev1.Action_ACTION_KILL_TEMP_MALWARE:
		return allowFrom(o, OriginReflex, a)
	case synapsev1.Action_ACTION_UNBAN:
		return allowFrom(o, OriginAutomation, a)
	case synapsev1.Action_ACTION_BAN_PERM, synapsev1.Action_ACTION_KILL_PROCESS,
		synapsev1.Action_ACTION_ISOLATE_HOST, synapsev1.Action_ACTION_RELEASE_HOST:
		return allowFrom(o, OriginAdmin, a)
	default:
		return refuse("rule unknown-action: %s", a)
	}
}

func validOrigin(o Origin) bool { return o >= OriginReflex && o <= OriginAdmin }

// allowFrom allows the action for origins at or above min.
func allowFrom(o, lowest Origin, a synapsev1.Action) Decision {
	if o < lowest {
		return refuse("rule origin-action: %s not permitted from this origin", a)
	}
	return Decision{Allowed: true}
}
