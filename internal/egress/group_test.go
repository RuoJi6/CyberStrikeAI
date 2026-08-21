package egress

import (
	"errors"
	"reflect"
	"testing"
)

func TestSelectSmoothWeightedIsStableAndHonorsWeights(t *testing.T) {
	state := []WeightedCandidate{
		{ID: "proxy-b", Weight: 1},
		{ID: "proxy-a", Weight: 3},
	}
	got := make([]string, 0, 8)
	for range 8 {
		selected, next, err := SelectSmoothWeighted(state)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, selected)
		state = next
	}
	want := []string{"proxy-a", "proxy-a", "proxy-b", "proxy-a", "proxy-a", "proxy-a", "proxy-b", "proxy-a"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selection order = %#v, want %#v", got, want)
	}
	counts := map[string]int{}
	for _, id := range got {
		counts[id]++
	}
	if counts["proxy-a"] != 6 || counts["proxy-b"] != 2 {
		t.Fatalf("selection counts = %#v", counts)
	}
}

func TestSelectSmoothWeightedRejectsInvalidState(t *testing.T) {
	if _, _, err := SelectSmoothWeighted(nil); !errors.Is(err, ErrNoWeightedCandidate) {
		t.Fatalf("empty error = %v", err)
	}
	for _, candidates := range [][]WeightedCandidate{
		{{ID: "", Weight: 1}},
		{{ID: "proxy", Weight: 0}},
		{{ID: "proxy", Weight: 1}, {ID: "proxy", Weight: 1}},
	} {
		if _, _, err := SelectSmoothWeighted(candidates); err == nil {
			t.Fatalf("SelectSmoothWeighted(%#v) succeeded", candidates)
		}
	}
}

func TestProxyGroupValidationBounds(t *testing.T) {
	if got, err := ValidateProxyGroupName(" Group "); err != nil || got != "Group" {
		t.Fatalf("name = %q / %v", got, err)
	}
	for _, value := range []int{0, MaxProxyGroupFailureCount + 1} {
		if err := ValidateProxyGroupFailureThreshold(value); err == nil {
			t.Fatalf("failure threshold %d accepted", value)
		}
	}
	for _, value := range []int{0, MaxProxyGroupCooldownSecs + 1} {
		if err := ValidateProxyGroupCooldownSeconds(value); err == nil {
			t.Fatalf("cooldown %d accepted", value)
		}
	}
	for _, pair := range [][2]int{{-1, 1}, {0, 0}, {MaxProxyGroupPriority + 1, 1}, {0, MaxProxyGroupMemberWeight + 1}} {
		if err := ValidateProxyGroupMember(pair[0], pair[1]); err == nil {
			t.Fatalf("member priority/weight %#v accepted", pair)
		}
	}
}
