package database

import (
	"context"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestConversationRuntimeControlsDefaultOffAndPersistEnabledValues(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "runtime-controls.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	conversation, err := db.CreateConversation("runtime controls", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer,
		RuntimeControls: ConversationRuntimeControls{
			HTTPRequestsPerSecond: 99, TCPConnectionsPerSecond: 88, UDPDatagramsPerSecond: 77,
			NanoCPUs: 2_000_000_000, MemoryBytes: 2 << 30,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	controls, err := db.GetConversationRuntimeControls(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if controls != (ConversationRuntimeControls{}) {
		t.Fatalf("disabled controls = %#v, want platform defaults", controls)
	}

	want := ConversationRuntimeControls{
		ScanRateEnabled: true, HTTPRequestsPerSecond: 25, TCPConnectionsPerSecond: 10, UDPDatagramsPerSecond: 5,
		CustomResourcesEnabled: true, NanoCPUs: 1_500_000_000, MemoryBytes: 768 << 20,
	}
	got, err := db.SetConversationRuntimeControls(context.Background(), conversation.ID, want)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("saved controls = %#v, want %#v", got, want)
	}
	loaded, err := db.GetConversationRuntimeControls(context.Background(), conversation.ID)
	if err != nil || loaded != want {
		t.Fatalf("loaded controls = %#v, err=%v", loaded, err)
	}
}

func TestConversationRuntimeControlsValidation(t *testing.T) {
	for name, value := range map[string]ConversationRuntimeControls{
		"enabled rate needs a protocol": {ScanRateEnabled: true},
		"rate has maximum":              {ScanRateEnabled: true, HTTPRequestsPerSecond: MaxConversationTrafficRate + 1},
		"cpu has minimum":               {CustomResourcesEnabled: true, NanoCPUs: MinConversationNanoCPUs - 1, MemoryBytes: MinConversationMemoryBytes},
		"memory has maximum":            {CustomResourcesEnabled: true, NanoCPUs: MinConversationNanoCPUs, MemoryBytes: MaxConversationMemoryBytes + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NormalizeConversationRuntimeControls(value); err == nil {
				t.Fatalf("NormalizeConversationRuntimeControls(%#v) accepted invalid value", value)
			}
		})
	}
}
