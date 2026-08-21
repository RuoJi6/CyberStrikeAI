// Package boundary contains the deterministic policy model used by the
// conversation egress boundary. Network enforcement is added in later stages;
// this package must stay independent from handlers and runtime providers.
package boundary

import (
	"fmt"
	"strings"
)

// Effect is the persisted access marker of a boundary rule.
type Effect string

const (
	EffectAllowVisit  Effect = "allow-visit"
	EffectAllowAttack Effect = "allow-attack"
	EffectBlocked     Effect = "blocked"
	EffectAuthOnly    Effect = "auth-only"
)

// ParseEffect accepts only the four access markers defined by the boundary
// policy contract. Whitespace is ignored, but aliases are deliberately not
// supported so persisted rules remain unambiguous.
func ParseEffect(value string) (Effect, error) {
	effect := Effect(strings.TrimSpace(value))
	if !effect.Valid() {
		return "", fmt.Errorf("invalid boundary rule effect %q", value)
	}
	return effect, nil
}

// Valid reports whether the effect belongs to the closed policy vocabulary.
func (e Effect) Valid() bool {
	switch e {
	case EffectAllowVisit, EffectAllowAttack, EffectBlocked, EffectAuthOnly:
		return true
	default:
		return false
	}
}

// AllowsRequest reports whether this marker represents an allow decision. The
// matching engine still has to apply precedence and all target constraints.
func (e Effect) AllowsRequest() bool {
	return e.Valid() && e != EffectBlocked
}

// RequiresAuthProfile reports whether the gateway must inject a configured
// credential profile instead of exposing credentials to the Agent.
func (e Effect) RequiresAuthProfile() bool {
	return e == EffectAuthOnly
}
