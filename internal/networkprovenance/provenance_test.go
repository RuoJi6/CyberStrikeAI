package networkprovenance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenRoundTripRejectsTamperingAndWrongAudience(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	signer.now = func() time.Time { return now }
	verifier, err := signer.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now.Add(time.Minute) }
	input := NetworkProvenanceV1{
		ConversationID: "conversation-1", RuntimeMode: RuntimeModeContainer, RuntimeGeneration: 4,
		RuntimeInstanceID: "gateway-1", AgentID: "lead", ToolName: "execute",
		ExecutionID: "execution-1", ToolCallID: "call-1", DeclaredActivityKind: ActivityKindNormal,
	}
	token, err := signer.Issue(input, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifier.Verify(token, ExpectedAudience{
		ConversationID: "conversation-1", RuntimeMode: RuntimeModeContainer,
		RuntimeGeneration: 4, RuntimeInstanceID: "gateway-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.AttributionStatus != AttributionVerified || got.ActivityScopeID != "call-1" || got.ToolName != "execute" {
		t.Fatalf("verified provenance = %#v", got)
	}
	parts := strings.Split(token, ".")
	parts[1] = parts[1][:len(parts[1])-1] + "A"
	if _, err := verifier.Verify(strings.Join(parts, "."), ExpectedAudience{}); err == nil {
		t.Fatal("tampered token was accepted")
	}
	for name, audience := range map[string]ExpectedAudience{
		"conversation": {ConversationID: "other"},
		"mode":         {RuntimeMode: RuntimeModeHostMITM},
		"generation":   {RuntimeGeneration: 5},
		"instance":     {RuntimeInstanceID: "gateway-2"},
	} {
		if _, err := verifier.Verify(token, audience); err == nil {
			t.Fatalf("wrong %s audience was accepted", name)
		}
	}
}

func TestTokenExpiryAndSigningKeyPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-attribution-signing.key")
	first, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicKeyEncoded() != second.PublicKeyEncoded() {
		t.Fatal("persisted signer changed public key")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v / %v", info, err)
	}
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	first.now = func() time.Time { return now }
	verifier, _ := first.Verifier()
	verifier.now = func() time.Time { return now.Add(2 * time.Hour) }
	token, err := first.Issue(NetworkProvenanceV1{
		ConversationID: "c", RuntimeMode: RuntimeModeHostMITM, RuntimeInstanceID: "h",
		AgentID: "host-agent", ToolName: "host-exec", ExecutionID: "e", DeclaredActivityKind: ActivityKindUnknown,
	}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(token, ExpectedAudience{}); err == nil {
		t.Fatal("expired token was accepted")
	}
}
