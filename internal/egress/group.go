package egress

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	MaxProxyGroupMembers      = 100
	MaxProxyGroupPriority     = 1_000_000
	MaxProxyGroupMemberWeight = 1_000
	MaxProxyGroupFailureCount = 100
	MaxProxyGroupCooldownSecs = 86_400
	DefaultProxyFailureCount  = 3
	DefaultProxyCooldownSecs  = 60
)

var ErrNoWeightedCandidate = errors.New("no weighted candidate")

// WeightedCandidate is the persisted state needed by smooth weighted
// round-robin. CurrentWeight is intentionally separate from the configured
// weight so routing state can be updated without changing configuration.
type WeightedCandidate struct {
	ID            string
	Weight        int
	CurrentWeight int64
}

func ValidateProxyGroupName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 120 || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("proxy group name must contain between 1 and 120 valid characters")
	}
	return value, nil
}

func ValidateProxyGroupFailureThreshold(value int) error {
	if value < 1 || value > MaxProxyGroupFailureCount {
		return fmt.Errorf("proxy group failure threshold must be between 1 and %d", MaxProxyGroupFailureCount)
	}
	return nil
}

func ValidateProxyGroupCooldownSeconds(value int) error {
	if value < 1 || value > MaxProxyGroupCooldownSecs {
		return fmt.Errorf("proxy group cooldown seconds must be between 1 and %d", MaxProxyGroupCooldownSecs)
	}
	return nil
}

func ValidateProxyGroupMember(priority, weight int) error {
	if priority < 0 || priority > MaxProxyGroupPriority {
		return fmt.Errorf("proxy group member priority must be between 0 and %d", MaxProxyGroupPriority)
	}
	if weight < 1 || weight > MaxProxyGroupMemberWeight {
		return fmt.Errorf("proxy group member weight must be between 1 and %d", MaxProxyGroupMemberWeight)
	}
	return nil
}

// SelectSmoothWeighted applies smooth weighted round-robin and returns the
// complete next state. Ties are resolved by stable ID order, making the result
// independent of database row order. Callers must persist every returned
// CurrentWeight atomically with the selected ID.
func SelectSmoothWeighted(candidates []WeightedCandidate) (string, []WeightedCandidate, error) {
	if len(candidates) == 0 {
		return "", nil, ErrNoWeightedCandidate
	}
	next := append([]WeightedCandidate(nil), candidates...)
	sort.Slice(next, func(i, j int) bool { return next[i].ID < next[j].ID })
	var total int64
	selected := -1
	seen := make(map[string]struct{}, len(next))
	for i := range next {
		next[i].ID = strings.TrimSpace(next[i].ID)
		if next[i].ID == "" {
			return "", nil, fmt.Errorf("weighted candidate id is required")
		}
		if _, exists := seen[next[i].ID]; exists {
			return "", nil, fmt.Errorf("weighted candidate id is duplicated")
		}
		seen[next[i].ID] = struct{}{}
		if next[i].Weight < 1 || next[i].Weight > MaxProxyGroupMemberWeight {
			return "", nil, fmt.Errorf("weighted candidate %s has invalid weight", next[i].ID)
		}
		weight := int64(next[i].Weight)
		if total > math.MaxInt64-weight || next[i].CurrentWeight > math.MaxInt64-weight {
			return "", nil, fmt.Errorf("weighted candidate state overflow")
		}
		total += weight
		next[i].CurrentWeight += weight
		if selected < 0 || next[i].CurrentWeight > next[selected].CurrentWeight {
			selected = i
		}
	}
	if selected < 0 || next[selected].CurrentWeight < math.MinInt64+total {
		return "", nil, fmt.Errorf("weighted candidate state overflow")
	}
	next[selected].CurrentWeight -= total
	return next[selected].ID, next, nil
}
