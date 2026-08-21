package boundary

import "testing"

func TestParseEffectAcceptsClosedVocabulary(t *testing.T) {
	tests := []struct {
		input               string
		want                Effect
		allows              bool
		requiresAuthProfile bool
	}{
		{input: "allow-visit", want: EffectAllowVisit, allows: true},
		{input: "allow-attack", want: EffectAllowAttack, allows: true},
		{input: "blocked", want: EffectBlocked},
		{input: " auth-only ", want: EffectAuthOnly, allows: true, requiresAuthProfile: true},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := ParseEffect(test.input)
			if err != nil || got != test.want {
				t.Fatalf("ParseEffect(%q) = %q, %v", test.input, got, err)
			}
			if got.AllowsRequest() != test.allows {
				t.Fatalf("AllowsRequest(%q) = %v", got, got.AllowsRequest())
			}
			if got.RequiresAuthProfile() != test.requiresAuthProfile {
				t.Fatalf("RequiresAuthProfile(%q) = %v", got, got.RequiresAuthProfile())
			}
		})
	}
}

func TestParseEffectRejectsAliasesAndUnknownValues(t *testing.T) {
	for _, input := range []string{"", "allow", "ALLOW-VISIT", "deny", "auth_only", "unknown"} {
		t.Run(input, func(t *testing.T) {
			if got, err := ParseEffect(input); err == nil || got != "" {
				t.Fatalf("ParseEffect(%q) = %q, %v", input, got, err)
			}
		})
	}
	if Effect("unknown").AllowsRequest() {
		t.Fatal("unknown effect must fail closed")
	}
}
