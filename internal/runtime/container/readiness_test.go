package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/egress"
	containerderrdefs "github.com/containerd/errdefs"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobymount "github.com/moby/moby/api/types/mount"
	mobynetwork "github.com/moby/moby/api/types/network"
)

func TestLoadToolInventoryPinsContentAndImageIdentity(t *testing.T) {
	raw := []byte(`{"schemaVersion":1,"imageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","imagePlatform":"linux/arm64","tools":[{"name":"sh","path":"/bin/sh","version":"busybox-1","category":"runtime"}]}`)
	digest := sha256.Sum256(raw)
	expected := "sha256:" + hex.EncodeToString(digest[:])
	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	inventory, actual, err := LoadToolInventory(path, expected)
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected || inventory.SchemaVersion != 1 || len(inventory.Tools) != 1 || inventory.Tools[0].Name != "sh" {
		t.Fatalf("inventory = %#v, digest = %s", inventory, actual)
	}
	if _, _, err := LoadToolInventory(path, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); !errors.Is(err, ErrImageDigestMismatch) {
		t.Fatalf("digest mismatch error = %v", err)
	}
	if err := ValidateReadinessPolicy(ReadinessPolicy{Enabled: true, InventoryDigest: expected, Inventory: inventory}, ImageReference{Digest: inventory.ImageDigest, Platform: inventory.ImagePlatform}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateToolInventoryRejectsUnsafeOrAmbiguousEntries(t *testing.T) {
	base := readinessInventory()
	tests := []struct {
		name   string
		mutate func(*ToolInventory)
	}{
		{name: "schema", mutate: func(inventory *ToolInventory) { inventory.SchemaVersion = 2 }},
		{name: "duplicate", mutate: func(inventory *ToolInventory) { inventory.Tools = append(inventory.Tools, inventory.Tools[0]) }},
		{name: "relative", mutate: func(inventory *ToolInventory) { inventory.Tools[0].Path = "bin/sh" }},
		{name: "clean", mutate: func(inventory *ToolInventory) { inventory.Tools[0].Path = "/bin/../bin/sh" }},
		{name: "docker socket", mutate: func(inventory *ToolInventory) { inventory.Tools[0].Path = "/var/run/docker.sock" }},
		{name: "missing version", mutate: func(inventory *ToolInventory) { inventory.Tools[0].Version = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inventory := base
			inventory.Tools = append([]ToolInventoryEntry(nil), base.Tools...)
			test.mutate(&inventory)
			if err := ValidateToolInventory(inventory); !errors.Is(err, ErrInvalidSpecification) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDockerManagerValidateReadinessChecksInventoryAndIsolation(t *testing.T) {
	spec := creationSpec()
	spec.Readiness = ReadinessPolicy{
		Enabled:         true,
		InventoryDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Inventory:       readinessInventory(),
	}
	ownerID := "instance-01"
	providerID := "provider-container-1"
	api := newSuccessfulCreationAPI(spec, ownerID, providerID, "")
	api.pathStats = map[string]mobycontainer.PathStat{
		"/bin/sh":      {Name: "sh", Mode: os.ModeSymlink | 0o777, LinkTarget: "/bin/busybox"},
		"/bin/busybox": {Name: "busybox", Mode: 0o755},
	}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	runtime := Runtime{ID: spec.ID, ConversationID: spec.ConversationID, ProviderID: providerID, Status: StatusStopped}
	report, err := manager.ValidateReadiness(context.Background(), runtime, spec)
	if err != nil {
		t.Fatal(err)
	}
	if report.InventoryDigest != spec.Readiness.InventoryDigest || report.ToolCount != 2 {
		t.Fatalf("report = %#v", report)
	}
}

func TestDockerManagerValidateReadinessRequiresOwnedInternalNetwork(t *testing.T) {
	spec := creationSpec()
	spec.Security.NetworkMode = NetworkInternal
	spec.Readiness = ReadinessPolicy{
		Enabled: true, InventoryDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Inventory: readinessInventory(),
	}
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := manager.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := manager.ValidateReadiness(context.Background(), runtime, spec); err != nil {
		t.Fatalf("internal readiness: %v", err)
	}
	name := ConversationNetworkName(spec.ID)
	network := api.networks[name]
	network.IPAM.Config[0].Gateway = netip.MustParseAddr("172.30.0.1")
	api.networks[name] = network
	endpoint := api.containerResult.Container.NetworkSettings.Networks[name]
	endpoint.Gateway = network.IPAM.Config[0].Gateway
	if _, err := manager.ValidateReadiness(context.Background(), runtime, spec); err != nil {
		t.Fatalf("matching inhibited gateway metadata: %v", err)
	}
	endpoint.Gateway = netip.MustParseAddr("172.30.0.254")
	if _, err := manager.ValidateReadiness(context.Background(), runtime, spec); !errors.Is(err, ErrRuntimeNotReady) || !strings.Contains(err.Error(), "gateway metadata") {
		t.Fatalf("drifted gateway metadata readiness error = %v", err)
	}
	endpoint.Gateway = network.IPAM.Config[0].Gateway
	network.Options[conversationNetworkGatewayModeIPv4] = "nat"
	api.networks[name] = network
	if _, err := manager.ValidateReadiness(context.Background(), runtime, spec); !errors.Is(err, ErrRuntimeNotReady) || !strings.Contains(err.Error(), "conversation network isolation") {
		t.Fatalf("drifted internal network readiness error = %v", err)
	}
}

func TestDockerManagerValidateReadinessAllowsOnlyOwnedWorkspaceVolume(t *testing.T) {
	spec := creationSpec()
	spec.Workspace.Persistent = true
	spec.Workspace.VolumeName = WorkspaceVolumeName(spec.ID)
	spec.Readiness = ReadinessPolicy{
		Enabled: true, InventoryDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Inventory: readinessInventory(),
	}
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.Mounts = []mobycontainer.MountPoint{{
		Type: mobymount.TypeVolume, Name: spec.Workspace.VolumeName,
		Destination: spec.Workspace.MountPath, RW: true,
	}}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	runtime := Runtime{ID: spec.ID, ConversationID: spec.ConversationID, ProviderID: "provider-container-1"}
	if _, err := manager.ValidateReadiness(context.Background(), runtime, spec); err != nil {
		t.Fatalf("persistent readiness: %v", err)
	}
	api.containerResult.Container.Mounts[0].Name = "foreign-volume"
	if _, err := manager.ValidateReadiness(context.Background(), runtime, spec); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("foreign mount error = %v", err)
	}
}

func TestReadinessAllowsOnlyReadOnlyTLSCertificateMountInAgent(t *testing.T) {
	spec := gatewayCreationSpec()
	spec.EgressGateway.BoundarySnapshot = &EgressBoundarySnapshotSpec{
		ID:     "12345678-1234-1234-1234-123456789abc",
		SHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	spec.EgressGateway.TLSAuthority = &EgressTLSAuthoritySpec{
		ID: "87654321-4321-4321-8321-cba987654321", BoundarySnapshotID: spec.EgressGateway.BoundarySnapshot.ID,
		CertificateSHA256: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		PrivateKeySHA256:  "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
	api := newSuccessfulGatewayCreationAPI(spec, "instance-01")
	agent := api.containerResults[runtimeContainerName(spec.ID)].Container
	agent.Mounts = []mobycontainer.MountPoint{{
		Type: mobymount.TypeBind, Source: "/trusted/tls/ca.crt",
		Destination: egress.TLSAuthorityCertificateContainerPath, RW: false,
	}}
	if err := verifyReadinessIsolation(agent, spec); err != nil {
		t.Fatalf("read-only Agent CA readiness: %v", err)
	}

	agent.Mounts[0].Destination = egress.TLSAuthorityPrivateKeyContainerPath
	if err := verifyReadinessIsolation(agent, spec); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Agent private-key mount was not rejected: %v", err)
	}
}

func TestDockerManagerValidateReadinessFailsClosed(t *testing.T) {
	makeManager := func(t *testing.T) (*DockerManager, *fakeDockerCreationAPI, RuntimeSpec, Runtime) {
		t.Helper()
		spec := creationSpec()
		spec.Readiness = ReadinessPolicy{
			Enabled:         true,
			InventoryDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Inventory:       readinessInventory(),
		}
		api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
		manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
		if err != nil {
			t.Fatal(err)
		}
		return manager, api, spec, Runtime{ID: spec.ID, ConversationID: spec.ConversationID, ProviderID: "provider-container-1"}
	}
	t.Run("missing tool", func(t *testing.T) {
		manager, api, spec, runtime := makeManager(t)
		api.pathStatErrs = map[string]error{"/bin/sh": containerderrdefs.ErrNotFound}
		if _, err := manager.ValidateReadiness(context.Background(), runtime, spec); !errors.Is(err, ErrRuntimeNotReady) || !strings.Contains(err.Error(), "inventory tool sh is missing at /bin/sh") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("inspection error is sanitized", func(t *testing.T) {
		manager, api, spec, runtime := makeManager(t)
		api.pathStatErrs = map[string]error{"/bin/sh": errors.New("dial unix /var/run/docker.sock: secret diagnostic")}
		_, err := manager.ValidateReadiness(context.Background(), runtime, spec)
		if !errors.Is(err, ErrRuntimeNotReady) || !strings.Contains(err.Error(), "inventory tool sh could not be inspected") || strings.Contains(err.Error(), "docker.sock") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("docker socket mount", func(t *testing.T) {
		manager, api, spec, runtime := makeManager(t)
		api.containerResult.Container.Mounts = []mobycontainer.MountPoint{{Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"}}
		if _, err := manager.ValidateReadiness(context.Background(), runtime, spec); !errors.Is(err, ErrRuntimeNotReady) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("network attachment", func(t *testing.T) {
		manager, api, spec, runtime := makeManager(t)
		api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{"bridge": {}}}
		if _, err := manager.ValidateReadiness(context.Background(), runtime, spec); !errors.Is(err, ErrRuntimeNotReady) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("not created", func(t *testing.T) {
		manager, api, spec, runtime := makeManager(t)
		api.containerResult.Container.State = &mobycontainer.State{Status: mobycontainer.StateRunning, Running: true}
		if _, err := manager.ValidateReadiness(context.Background(), runtime, spec); !errors.Is(err, ErrRuntimeNotReady) {
			t.Fatalf("error = %v", err)
		}
	})
}

func readinessInventory() ToolInventory {
	return ToolInventory{
		SchemaVersion: ToolInventorySchemaVersion,
		ImageDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImagePlatform: "linux/arm64",
		Tools: []ToolInventoryEntry{
			{Name: "sh", Path: "/bin/sh", Version: "busybox-1", Category: "runtime"},
			{Name: "busybox", Path: "/bin/busybox", Version: "busybox-1", Category: "utility"},
		},
	}
}
