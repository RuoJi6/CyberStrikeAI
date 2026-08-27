package database

import (
	"context"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/traffictransform"

	"go.uber.org/zap"
)

const testTransformSource = `from cyberstrike_transform import Message

def decode_request(ctx, wire: Message) -> Message:
    return wire
`

func TestTrafficTransformRevisionBindingLifecycle(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "traffic-transform.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	conversation, err := db.CreateConversation("transform", ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	transform, err := db.CreateTrafficTransform(ctx, &traffictransform.Transform{
		ConversationID:   conversation.ID,
		Name:             "encrypted API codec",
		Description:      "decode and re-encode an application payload",
		CreatedByAgentID: "agent-1",
	})
	if err != nil {
		t.Fatalf("CreateTrafficTransform: %v", err)
	}
	revision, report, err := db.CreateTrafficTransformRevision(ctx, &traffictransform.Revision{
		TransformID:      transform.ID,
		Source:           testTransformSource,
		Hooks:            []traffictransform.Hook{traffictransform.HookDecodeRequest},
		Requirements:     []string{"cryptography==38.0.4"},
		CreatedByAgentID: "agent-1",
	}, traffictransform.DefaultRunnerInventory())
	if err != nil {
		t.Fatalf("CreateTrafficTransformRevision: %v", err)
	}
	if !report.Valid || revision.ValidationStatus != traffictransform.ValidationPending {
		t.Fatalf("static validation = %#v / %#v", revision, report)
	}
	if _, _, err := db.CreateTrafficTransformRevision(ctx, &traffictransform.Revision{
		TransformID: transform.ID, Source: testTransformSource, Hooks: []traffictransform.Hook{traffictransform.HookDecodeRequest},
	}, traffictransform.DefaultRunnerInventory()); err == nil {
		t.Fatal("expected an identical immutable revision to be deduplicated")
	}

	report.Runner = "test-runner"
	if err := db.SetTrafficTransformRevisionValidation(ctx, revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, report); err != nil {
		t.Fatalf("SetTrafficTransformRevisionValidation: %v", err)
	}
	revision, err = db.GetTrafficTransformRevision(ctx, revision.ID)
	if err != nil || revision.ValidationStatus != traffictransform.ValidationPassed || revision.Source != testTransformSource {
		t.Fatalf("GetTrafficTransformRevision = %#v / %v", revision, err)
	}

	binding, err := db.CreateTrafficTransformBinding(ctx, &traffictransform.Binding{
		ConversationID: conversation.ID,
		TransformID:    transform.ID,
		RevisionID:     revision.ID,
		Mode:           traffictransform.ModeObserve,
		Matcher:        traffictransform.Matcher{Hosts: []string{"API.Example.Test"}, PathPrefixes: []string{"/v1/"}},
		Priority:       100,
	})
	if err != nil {
		t.Fatalf("CreateTrafficTransformBinding: %v", err)
	}
	if binding.Status != traffictransform.BindingDraft || binding.Matcher.Hosts[0] != "api.example.test" {
		t.Fatalf("draft binding = %#v", binding)
	}
	binding, err = db.ActivateTrafficTransformBinding(ctx, binding.ID, "")
	if err != nil || binding.Status != traffictransform.BindingActive || binding.ApprovedAt != nil {
		t.Fatalf("ActivateTrafficTransformBinding = %#v / %v", binding, err)
	}
	active, err := db.ListActiveTrafficTransformBindings(ctx, conversation.ID)
	if err != nil || len(active) != 1 || active[0].ID != binding.ID {
		t.Fatalf("ListActiveTrafficTransformBindings = %#v / %v", active, err)
	}
	if _, err := db.DisableTrafficTransformBinding(ctx, binding.ID); err != nil {
		t.Fatalf("DisableTrafficTransformBinding: %v", err)
	}
	active, err = db.ListActiveTrafficTransformBindings(ctx, conversation.ID)
	if err != nil || len(active) != 0 {
		t.Fatalf("active after disable = %#v / %v", active, err)
	}

	list, err := db.ListTrafficTransformsForConversation(ctx, conversation.ID)
	if err != nil || len(list) != 1 || list[0].ID != transform.ID {
		t.Fatalf("ListTrafficTransformsForConversation = %#v / %v", list, err)
	}
}

func TestInlineTrafficTransformBindingRequiresApprovingUser(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "traffic-transform-inline.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	conversation, _ := db.CreateConversation("inline", ConversationCreateMeta{})
	transform, _ := db.CreateTrafficTransform(ctx, &traffictransform.Transform{ConversationID: conversation.ID, Name: "inline codec"})
	revision, report, err := db.CreateTrafficTransformRevision(ctx, &traffictransform.Revision{
		TransformID: transform.ID, Source: testTransformSource, Hooks: []traffictransform.Hook{traffictransform.HookDecodeRequest},
	}, traffictransform.DefaultRunnerInventory())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetTrafficTransformRevisionValidation(ctx, revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, report); err != nil {
		t.Fatal(err)
	}
	binding, err := db.CreateTrafficTransformBinding(ctx, &traffictransform.Binding{
		ConversationID: conversation.ID, TransformID: transform.ID, RevisionID: revision.ID,
		Mode: traffictransform.ModeInline,
	})
	if err != nil {
		t.Fatalf("CreateTrafficTransformBinding: %v", err)
	}
	if _, err := db.ActivateTrafficTransformBinding(ctx, binding.ID, ""); err == nil {
		t.Fatal("expected inline activation without an approving user to fail")
	}
	activated, err := db.ActivateTrafficTransformBinding(ctx, binding.ID, "reviewer-1")
	if err != nil || activated.ApprovedByUserID != "reviewer-1" || activated.ApprovedAt == nil {
		t.Fatalf("approved inline binding = %#v / %v", activated, err)
	}
}
