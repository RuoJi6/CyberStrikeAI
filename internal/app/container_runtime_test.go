package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/networkprovenance"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"go.uber.org/zap"
)

func TestMaterializeConversationTLSAuthorityIsConversationScopedStableAndRotates(t *testing.T) {
	store, err := egress.NewTLSAuthorityStore(filepath.Join(t.TempDir(), "tls-authorities"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := database.ConversationBoundarySnapshot{
		SnapshotID: "12345678-1234-1234-1234-123456789abc", ConversationID: "conversation-one",
		Document: database.BoundaryPolicySnapshotDocument{
			SchemaVersion: 2, TLSInspection: &database.BoundaryPolicyTLSInspectionSnapshot{Enabled: true, BypassDomains: []string{}},
		},
	}
	now := time.Unix(1_788_000_000, 0).UTC()
	first, err := materializeConversationTLSAuthorityAt(store, snapshot, now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := materializeConversationTLSAuthorityAt(store, snapshot, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if first == nil || retry == nil || *first != *retry || first.ID == snapshot.SnapshotID || first.BoundarySnapshotID != snapshot.SnapshotID {
		t.Fatalf("stable authority references = %#v / %#v", first, retry)
	}
	rotated, err := materializeConversationTLSAuthorityAt(store, snapshot, now.Add(tlsAuthorityRotationPeriod))
	if err != nil {
		t.Fatal(err)
	}
	if rotated == nil || rotated.ID == first.ID || rotated.CertificateSHA256 == first.CertificateSHA256 {
		t.Fatalf("rotated authority reference = %#v, original %#v", rotated, first)
	}
	other := snapshot
	other.SnapshotID = "87654321-4321-4321-4321-cba987654321"
	other.ConversationID = "conversation-two"
	isolated, err := materializeConversationTLSAuthorityAt(store, other, now)
	if err != nil {
		t.Fatal(err)
	}
	if isolated == nil || isolated.ID == first.ID || isolated.CertificateSHA256 == first.CertificateSHA256 || isolated.BoundarySnapshotID != other.SnapshotID {
		t.Fatalf("conversation authority isolation = %#v / %#v", first, isolated)
	}
}

func TestConversationContainerSpecUsesTrustedPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.Container.Enabled = true
	cfg.Container.OwnerID = "deployment-01"
	cfg.Container.ImageRepository = "ghcr.io/usestrix/strix-sandbox"
	cfg.Container.ImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfg.Container.ImagePlatform = "linux/arm64"
	cfg.Container.EgressImageRepository = "ghcr.io/example/cyberstrike-egress"
	cfg.Container.EgressImageDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	cfg.Container.EgressImagePlatform = "linux/arm64"
	cfg.Container.ToolInventoryPath = "inventory.json"
	cfg.Container.ToolInventoryDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cfg.Container.ToolInventory = containerruntime.ToolInventory{
		SchemaVersion: containerruntime.ToolInventorySchemaVersion,
		ImageDigest:   cfg.Container.ImageDigest,
		ImagePlatform: cfg.Container.ImagePlatform,
		Tools: []containerruntime.ToolInventoryEntry{
			{Name: "sh", Path: "/bin/sh", Version: "busybox-1", Category: "runtime"},
		},
	}
	snapshot := containerruntime.EgressBoundarySnapshotSpec{
		ID: "12345678-1234-1234-1234-123456789abc", SHA256: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
	spec, err := conversationContainerSpec(cfg, "conversation-01", false, snapshot, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if spec.ID != "conversation-conversation-01" || spec.ConversationID != "conversation-01" || spec.Image.Repository != cfg.Container.ImageRepository || spec.Image.Digest != cfg.Container.ImageDigest {
		t.Fatalf("spec identity = %#v", spec)
	}
	if spec.Security.NetworkMode != containerruntime.NetworkInternal || !spec.Security.ReadOnlyRootFS || !spec.Security.NoNewPrivileges || !spec.Security.DropAllCapabilities || spec.Security.SeccompProfile != "default" {
		t.Fatalf("spec security = %#v", spec.Security)
	}
	if spec.Resources.MemoryBytes != 512<<20 || spec.Resources.MaxConcurrentExec != 2 || spec.Resources.MaxQueuedExec != 8 || spec.Resources.LogMaxFiles != 3 {
		t.Fatalf("spec resources = %#v", spec.Resources)
	}
	if spec.EgressGateway == nil || spec.EgressGateway.Image.Digest != cfg.Container.EgressImageDigest || spec.EgressGateway.Resources.MemoryBytes != 128<<20 || spec.EgressGateway.BoundarySnapshot == nil || *spec.EgressGateway.BoundarySnapshot != snapshot {
		t.Fatalf("egress gateway = %#v", spec.EgressGateway)
	}
	if !spec.Readiness.Enabled || spec.Readiness.InventoryDigest != cfg.Container.ToolInventoryDigest || len(spec.Readiness.Inventory.Tools) != 1 {
		t.Fatalf("spec readiness = %#v", spec.Readiness)
	}
	signer, err := networkprovenance.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.RuntimeGeneration = 4
	attributed, err := conversationContainerSpec(cfg, "conversation-attributed", false, snapshot, nil, nil, nil, signer.PublicKeyEncoded())
	if err != nil {
		t.Fatal(err)
	}
	if attributed.EgressGateway == nil || attributed.EgressGateway.AttributionPublicKey != signer.PublicKeyEncoded() ||
		attributed.EgressGateway.AttributionRuntimeGeneration != 4 || attributed.EgressGateway.AttributionInstanceID == "" ||
		attributed.EgressGateway.AttributionInstanceID == snapshot.ID {
		t.Fatalf("attributed gateway binding = %#v", attributed.EgressGateway)
	}
}

func TestMaterializeConversationAuthProfilesIsGatewayOnlyAndFailsClosed(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "auth-materialization.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cipher, err := egress.NewCredentialCipher(bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret := "Bearer materialized-secret"
	ciphertext, err := cipher.EncryptAuthProfile("profile-1", []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := db.CreateEgressAuthProfile(t.Context(), database.EgressAuthProfile{
		ID: "profile-1", Name: "Target credential", HeaderName: "Authorization", Enabled: true,
		CredentialCiphertext: ciphertext, OwnerUserID: "owner-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	profileID := profile.ID
	snapshot := database.ConversationBoundarySnapshot{
		SnapshotID: "11111111-1111-4111-8111-111111111111",
		Document: database.BoundaryPolicySnapshotDocument{SchemaVersion: 1, PolicyID: "policy-1", Rules: []database.BoundaryPolicySnapshotRule{{
			ID: "rule-1", Effect: boundary.EffectAuthOnly, Host: "api.example",
			Schemes: []string{"http"}, Ports: []int{}, PathPrefixes: []string{}, Methods: []string{},
			AuthProfileID: &profileID,
		}}},
	}
	store, err := egress.NewAuthProfilesStore(filepath.Join(t.TempDir(), "auth-profiles"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := materializeConversationAuthProfiles(t.Context(), db, cipher, store, snapshot)
	if err != nil || spec == nil {
		t.Fatalf("auth profiles spec = %#v, %v", spec, err)
	}
	if strings.Contains(spec.ID+spec.SHA256, secret) {
		t.Fatal("safe runtime auth profiles reference exposed credential")
	}
	wantPrefix := "auth-" + snapshot.SnapshotID + "-"
	if !strings.HasPrefix(spec.ID, wantPrefix) || len(strings.TrimPrefix(spec.ID, wantPrefix)) != 16 {
		t.Fatalf("auth profiles reference %q is not bound to snapshot %q", spec.ID, snapshot.SnapshotID)
	}
	loaded, err := egress.LoadAuthProfiles(filepath.Join(store.Root(), spec.ID+".json"), egress.AuthProfilesReference{ID: spec.ID, SHA256: spec.SHA256})
	if err != nil || len(loaded.Profiles) != 1 || loaded.Profiles[0].HeaderValue != secret {
		t.Fatalf("loaded gateway auth profiles = %#v, %v", loaded, err)
	}
	profile.Enabled = false
	if _, err := db.UpdateEgressAuthProfile(t.Context(), profile); err != nil {
		t.Fatal(err)
	}
	if _, err := materializeConversationAuthProfiles(t.Context(), db, cipher, store, snapshot); err == nil {
		t.Fatal("disabled auth profile was materialized")
	}
	noAuth := snapshot
	noAuth.Document.Rules = nil
	if spec, err := materializeConversationAuthProfiles(t.Context(), db, cipher, store, noAuth); err != nil || spec != nil {
		t.Fatalf("no-auth snapshot materialization = %#v, %v", spec, err)
	}
}

func TestBoundarySnapshotInitializationStoreBindsBeforeWorkerClaim(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "initializer-boundary.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("queued", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	spec := appExecutionSpec(conversation.ID)
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		t.Fatal(err)
	}
	snapshotStore, err := egress.NewSnapshotStore(filepath.Join(t.TempDir(), "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	tlsAuthorityStore, err := egress.NewTLSAuthorityStore(filepath.Join(t.TempDir(), "tls-authorities"))
	if err != nil {
		t.Fatal(err)
	}
	gateway := containerruntime.EgressGatewaySpec{
		Image: containerruntime.ImageReference{
			Repository: "ghcr.io/example/cyberstrike-egress",
			Digest:     "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			Platform:   "linux/arm64",
		},
		Resources: containerruntime.EgressGatewayResources{
			NanoCPUs: 250_000_000, MemoryBytes: 128 << 20, PIDs: 64,
			NoFileSoft: 512, NoFileHard: 1024, TmpfsBytes: 16 << 20,
			LogMaxBytes: 2 << 20, LogMaxFiles: 2,
		},
	}
	store := &boundarySnapshotInitializationStore{DB: db, SnapshotStore: snapshotStore, TLSAuthorityStore: tlsAuthorityStore, EgressGateway: &gateway}
	claimedRecord, claimed, err := store.Claim(context.Background(), conversation.ID)
	if err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	if _, err := db.GetConversationBoundarySnapshot(context.Background(), conversation.ID); err != nil {
		t.Fatalf("worker claim did not bind snapshot first: %v", err)
	}
	conversationEgress, err := db.GetConversationEgressBinding(context.Background(), conversation.ID)
	if err != nil || conversationEgress.State != database.ConversationEgressStateActive || conversationEgress.Mode != database.ConversationEgressModeNone || conversationEgress.Source != database.ConversationEgressSourceNone {
		t.Fatalf("worker claim did not bind upstream egress first: %#v / %v", conversationEgress, err)
	}
	bound, err := db.GetConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := egress.LoadSnapshot(filepath.Join(snapshotStore.Root(), bound.SnapshotID+".json"), egress.SnapshotReference{ID: bound.SnapshotID, SHA256: bound.SHA256}); err != nil {
		t.Fatalf("worker claim did not materialize snapshot first: %v", err)
	}
	if claimedRecord.Spec.Security.NetworkMode != containerruntime.NetworkInternal || claimedRecord.Spec.EgressGateway == nil || claimedRecord.Spec.EgressGateway.BoundarySnapshot == nil || claimedRecord.Spec.EgressGateway.BoundarySnapshot.ID != bound.SnapshotID || claimedRecord.Spec.EgressGateway.BoundarySnapshot.SHA256 != bound.SHA256 || claimedRecord.Spec.EgressGateway.TLSAuthority == nil || claimedRecord.Spec.EgressGateway.TLSAuthority.BoundarySnapshotID != bound.SnapshotID {
		t.Fatalf("worker claim did not upgrade queued topology: %#v", claimedRecord.Spec)
	}
}

func TestBoundarySnapshotInitializationStoreFailsClosedWhenEgressBindingCannotPersist(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "initializer-egress-failure.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("queued", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.Queue(context.Background(), appExecutionSpec(conversation.ID), false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE conversation_egress_bindings`); err != nil {
		t.Fatal(err)
	}
	snapshotStore, err := egress.NewSnapshotStore(filepath.Join(t.TempDir(), "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	store := &boundarySnapshotInitializationStore{DB: db, SnapshotStore: snapshotStore}
	if _, claimed, err := store.Claim(context.Background(), conversation.ID); err == nil || claimed {
		t.Fatalf("claim = %v / %v, want fail closed", claimed, err)
	}
	record, err := db.GetContainerInitialization(context.Background(), conversation.ID)
	if err != nil || record.Status != containerruntime.InitializationQueued {
		t.Fatalf("record after rejected claim = %#v / %v", record, err)
	}
	if _, err := db.GetConversationBoundarySnapshot(context.Background(), conversation.ID); !errors.Is(err, database.ErrConversationBoundarySnapshotNotFound) {
		t.Fatalf("boundary froze after egress failure: %v", err)
	}
}

func TestConversationContainerSpecUsesConversationNamedVolume(t *testing.T) {
	cfg := config.Default()
	cfg.Container.Enabled = true
	cfg.Container.ImageRepository = "ghcr.io/usestrix/strix-sandbox"
	cfg.Container.ImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfg.Container.ImagePlatform = "linux/arm64"
	cfg.Container.EgressImageRepository = "ghcr.io/example/cyberstrike-egress"
	cfg.Container.EgressImageDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	cfg.Container.EgressImagePlatform = "linux/arm64"
	cfg.Container.ToolInventoryDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cfg.Container.ToolInventory = containerruntime.ToolInventory{
		SchemaVersion: containerruntime.ToolInventorySchemaVersion,
		ImageDigest:   cfg.Container.ImageDigest, ImagePlatform: cfg.Container.ImagePlatform,
		Tools: []containerruntime.ToolInventoryEntry{{Name: "sh", Path: "/bin/sh", Version: "busybox-1", Category: "runtime"}},
	}
	spec, err := conversationContainerSpec(cfg, "conversation-01", true, containerruntime.EgressBoundarySnapshotSpec{
		ID: "12345678-1234-1234-1234-123456789abc", SHA256: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Workspace.Persistent || spec.Workspace.VolumeName != "cyberstrike-workspace-conversation-conversation-01" {
		t.Fatalf("workspace = %#v", spec.Workspace)
	}
}

func TestMaterializeConversationUpstreamRouteKeepsSecretsGatewayOnlyAndFailsClosed(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "upstream-route.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cipher, err := egress.NewCredentialCipher(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	credentials, _ := json.Marshal(egress.ProxyCredentials{Username: "gateway-user", Password: "gateway-secret"})
	ciphertext, err := cipher.Encrypt("proxy-a", credentials)
	if err != nil {
		t.Fatal(err)
	}
	proxyA, err := db.CreateEgressProxy(context.Background(), database.EgressProxy{
		ID: "proxy-a", Name: "Proxy A", Protocol: egress.UpstreamProtocolHTTP,
		Host: "proxy.example", Port: 3128, Enabled: true, OwnerUserID: "owner-1",
		CredentialCiphertext: ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyB, err := db.CreateEgressProxy(context.Background(), database.EgressProxy{
		ID: "proxy-b", Name: "Proxy B", Protocol: egress.UpstreamProtocolSOCKS5,
		Host: "disabled.proxy.example", Port: 1080, Enabled: false, OwnerUserID: "owner-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := egress.NewUpstreamRouteStore(filepath.Join(t.TempDir(), "routes"))
	if err != nil {
		t.Fatal(err)
	}

	proxyConversation, err := db.CreateConversation("proxy route", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetConversationEgressSelection(context.Background(), proxyConversation.ID, database.ConversationEgressModeProxy, proxyA.ID, ""); err != nil {
		t.Fatal(err)
	}
	proxyBinding, err := db.EnsureConversationEgressBinding(context.Background(), proxyConversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	proxySpec, err := materializeConversationUpstreamRoute(context.Background(), db, cipher, store, proxyBinding)
	if err != nil || proxySpec == nil {
		t.Fatalf("proxy route spec = %#v, err=%v", proxySpec, err)
	}
	loadedProxy, err := egress.LoadUpstreamRoute(filepath.Join(store.Root(), proxySpec.ID+".json"), egress.UpstreamRouteReference{ID: proxySpec.ID, SHA256: proxySpec.SHA256})
	if err != nil || loadedProxy.Proxy == nil || loadedProxy.Proxy.Username != "gateway-user" || loadedProxy.Proxy.Password != "gateway-secret" {
		t.Fatalf("loaded proxy route = %#v, err=%v", loadedProxy, err)
	}
	safeSpec, _ := json.Marshal(proxySpec)
	if bytes.Contains(safeSpec, []byte("gateway-user")) || bytes.Contains(safeSpec, []byte("gateway-secret")) || bytes.Contains(safeSpec, []byte(ciphertext)) {
		t.Fatal("runtime route reference exposed credentials")
	}

	group, err := db.CreateEgressProxyGroup(context.Background(), database.EgressProxyGroup{
		ID: "group-a", Name: "Group A", Enabled: true, FailureThreshold: 2, CooldownSeconds: 30,
		OwnerUserID: "owner-1", Members: []database.EgressProxyGroupMember{
			{ProxyID: proxyA.ID, Priority: 0, Weight: 3, Enabled: true},
			{ProxyID: proxyB.ID, Priority: 1, Weight: 1, Enabled: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	groupConversation, err := db.CreateConversation("group route", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetConversationEgressSelection(context.Background(), groupConversation.ID, database.ConversationEgressModeGroup, "", group.ID); err != nil {
		t.Fatal(err)
	}
	groupBinding, err := db.EnsureConversationEgressBinding(context.Background(), groupConversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	groupSpec, err := materializeConversationUpstreamRoute(context.Background(), db, cipher, store, groupBinding)
	if err != nil || groupSpec == nil {
		t.Fatalf("group route spec = %#v, err=%v", groupSpec, err)
	}
	loadedGroup, err := egress.LoadUpstreamRoute(filepath.Join(store.Root(), groupSpec.ID+".json"), egress.UpstreamRouteReference{ID: groupSpec.ID, SHA256: groupSpec.SHA256})
	if err != nil || loadedGroup.Group == nil || len(loadedGroup.Group.Members) != 1 || loadedGroup.Group.Members[0].Proxy.ID != proxyA.ID {
		t.Fatalf("loaded group route = %#v, err=%v", loadedGroup, err)
	}

	disabledConversation, err := db.CreateConversation("disabled route", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetConversationEgressSelection(context.Background(), disabledConversation.ID, database.ConversationEgressModeProxy, proxyB.ID, ""); err != nil {
		t.Fatal(err)
	}
	disabledBinding, err := db.EnsureConversationEgressBinding(context.Background(), disabledConversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := materializeConversationUpstreamRoute(context.Background(), db, cipher, store, disabledBinding); !errors.Is(err, database.ErrNoAvailableEgressProxy) {
		t.Fatalf("disabled proxy route error = %v", err)
	}
}
