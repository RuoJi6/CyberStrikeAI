package traffic

import (
	"bytes"
	"testing"
	"time"
)

func TestMessageBodyRoundTripAndCompletenessValidation(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xff, 0x10}
	body, encoding, digest := EncodeBody(raw)
	message := Message{
		Stage: StageClientRequest, Kind: MessageKindRequest, Method: "POST", Path: "/encrypted",
		Headers: []Header{{Name: "Content-Type", Value: "application/octet-stream"}},
		Body:    body, BodyEncoding: encoding, BodySHA256: digest,
		BodyLength: int64(len(raw)), BodyStoredBytes: int64(len(raw)), Complete: true,
	}
	if err := ValidateMessage(message); err != nil {
		t.Fatalf("ValidateMessage: %v", err)
	}
	decoded, err := DecodeBody(message)
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatalf("DecodeBody = %x, %v", decoded, err)
	}

	message.BodyLength++
	if err := ValidateMessage(message); err == nil {
		t.Fatal("expected a complete message with mismatched body length to be rejected")
	}
	message.Complete = false
	if err := ValidateMessage(message); err != nil {
		t.Fatalf("truncated message should be valid: %v", err)
	}
}

func TestValidateTransactionRejectsInvalidTargetAndTime(t *testing.T) {
	started := time.Now().UTC()
	completed := started.Add(-time.Second)
	item := Transaction{
		ConversationID: "conversation-1", Scheme: "https", Host: "example.test", Port: 443,
		Method: "GET", Path: "/", StartedAt: started, CompletedAt: &completed,
	}
	if err := ValidateTransaction(item); err == nil {
		t.Fatal("expected completion before start to be rejected")
	}
	item.CompletedAt = nil
	item.Host = ""
	if err := ValidateTransaction(item); err == nil {
		t.Fatal("expected empty host to be rejected")
	}
}
