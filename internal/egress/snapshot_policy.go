package egress

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"time"

	"cyberstrike-ai/internal/boundary"
)

type snapshotPolicyRule struct {
	ID            string            `json:"id"`
	Effect        boundary.Effect   `json:"effect"`
	Host          string            `json:"host"`
	Schemes       []string          `json:"schemes"`
	Ports         []int             `json:"ports"`
	PathPrefixes  []string          `json:"pathPrefixes"`
	Methods       []string          `json:"methods"`
	AuthProfileID *string           `json:"authProfileId"`
	RateLimit     snapshotRateLimit `json:"rateLimit"`
	ExpiresAt     *time.Time        `json:"expiresAt"`
	Position      int               `json:"position"`
}

type snapshotRateLimit struct {
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	Burst             int     `json:"burst"`
}

func compileSnapshotPolicy(encodedRules []json.RawMessage) (*boundary.Policy, error) {
	rules := make([]boundary.Rule, 0, len(encodedRules))
	for index, encoded := range encodedRules {
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		var stored snapshotPolicyRule
		if err := decoder.Decode(&stored); err != nil {
			return nil, fmt.Errorf("%w: decode rule %d: %v", ErrSnapshotIntegrity, index, err)
		}
		var extra interface{}
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: rule %d contains trailing data", ErrSnapshotIntegrity, index)
		}
		if stored.ID == "" || stored.ID != strings.TrimSpace(stored.ID) || stored.Schemes == nil || stored.Ports == nil || stored.PathPrefixes == nil || stored.Methods == nil {
			return nil, fmt.Errorf("%w: rule %d is not canonical", ErrSnapshotIntegrity, index)
		}
		if math.IsNaN(stored.RateLimit.RequestsPerSecond) || math.IsInf(stored.RateLimit.RequestsPerSecond, 0) || stored.RateLimit.RequestsPerSecond < 0 || stored.RateLimit.Burst < 0 || (stored.RateLimit.RequestsPerSecond == 0) != (stored.RateLimit.Burst == 0) {
			return nil, fmt.Errorf("%w: rule %d rate limit is invalid", ErrSnapshotIntegrity, index)
		}
		target := boundary.RuleTarget{
			Host: stored.Host, Schemes: stored.Schemes, Ports: stored.Ports,
			PathPrefixes: stored.PathPrefixes, Methods: stored.Methods,
		}
		normalized, err := boundary.NormalizeRuleTarget(target)
		if err != nil || !reflect.DeepEqual(normalized, target) {
			return nil, fmt.Errorf("%w: rule %d target is not canonical", ErrSnapshotIntegrity, index)
		}
		authProfileID := ""
		if stored.AuthProfileID != nil {
			authProfileID = *stored.AuthProfileID
			if authProfileID == "" || authProfileID != strings.TrimSpace(authProfileID) {
				return nil, fmt.Errorf("%w: rule %d auth profile is not canonical", ErrSnapshotIntegrity, index)
			}
		}
		rules = append(rules, boundary.Rule{
			ID: stored.ID, Effect: stored.Effect, Target: target,
			AuthProfileID: authProfileID, ExpiresAt: stored.ExpiresAt,
		})
	}
	policy, err := boundary.NewPolicy(rules)
	if err != nil {
		return nil, fmt.Errorf("%w: compile boundary policy: %v", ErrSnapshotIntegrity, err)
	}
	return policy, nil
}
