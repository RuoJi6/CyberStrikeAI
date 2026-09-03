package security

import (
	"reflect"
	"testing"

	"cyberstrike-ai/internal/networkprovenance"
)

func TestConsumeNetworkScopeAcceptsOnlyExplicitFuzzWrapper(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
		kind string
		err  bool
	}{
		{name: "argv", in: []string{"network-scope", "fuzz", "--", "curl", "https://example.test/FUZZ"}, want: []string{"curl", "https://example.test/FUZZ"}, kind: networkprovenance.ActivityKindFuzz},
		{name: "shell", in: []string{"/bin/sh", "-c", "network-scope fuzz -- curl https://example.test/FUZZ"}, want: []string{"/bin/sh", "-c", "curl https://example.test/FUZZ"}, kind: networkprovenance.ActivityKindFuzz},
		{name: "ordinary", in: []string{"curl", "https://example.test/FUZZ"}, want: []string{"curl", "https://example.test/FUZZ"}},
		{name: "invalid", in: []string{"network-scope", "normal", "--", "curl", "https://example.test"}, err: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, kind, err := ConsumeNetworkScope(ExecutionRequest{Command: test.in})
			if (err != nil) != test.err || kind != test.kind || (!test.err && !reflect.DeepEqual(got.Command, test.want)) {
				t.Fatalf("got command=%#v kind=%q err=%v", got.Command, kind, err)
			}
		})
	}
}
