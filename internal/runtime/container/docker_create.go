package container

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	containerderrdefs "github.com/containerd/errdefs"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobyclient "github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	LabelManaged        = "com.cyberstrike.managed"
	LabelOwner          = "com.cyberstrike.owner"
	LabelRuntimeID      = "com.cyberstrike.runtime-id"
	LabelConversationID = "com.cyberstrike.conversation-id"
	LabelResourceKind   = "com.cyberstrike.resource-kind"
	LabelImageDigest    = "com.cyberstrike.image-digest"
	LabelImagePlatform  = "com.cyberstrike.image-platform"
	ResourceKindAgent   = "agent-runtime"
)

type dockerCreationAPI interface {
	dockerInspectionAPI
	ContainerCreate(context.Context, mobyclient.ContainerCreateOptions) (mobyclient.ContainerCreateResult, error)
	ContainerRemove(context.Context, string, mobyclient.ContainerRemoveOptions) (mobyclient.ContainerRemoveResult, error)
}

// DockerManagerOptions contains control-plane identity, never request data.
type DockerManagerOptions struct {
	OwnerID string
}

// DockerManager incrementally implements the RuntimeManager contract. At this
// stage it supports read-only inspection and create-only lifecycle operations.
type DockerManager struct {
	*DockerInspector
	api     dockerCreationAPI
	ownerID string
}

var _ RuntimeCreator = (*DockerManager)(nil)

func NewDockerManagerFromEnvironment(options DockerManagerOptions) (*DockerManager, error) {
	api, err := mobyclient.New(mobyclient.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize engine client: %v", ErrEngineUnavailable, err)
	}
	manager, err := newDockerManager(api, options)
	if err != nil {
		_ = api.Close()
		return nil, err
	}
	manager.DockerInspector.closer = api
	return manager, nil
}

func newDockerManager(api dockerCreationAPI, options DockerManagerOptions) (*DockerManager, error) {
	ownerID := strings.TrimSpace(options.OwnerID)
	if !generatedNamePattern.MatchString(ownerID) {
		return nil, fmt.Errorf("%w: owner id is required and must be label-safe", ErrInvalidSpecification)
	}
	inspector := newDockerInspector(api)
	return &DockerManager{DockerInspector: inspector, api: api, ownerID: ownerID}, nil
}

func (m *DockerManager) Create(ctx context.Context, spec RuntimeSpec) (Runtime, error) {
	if m == nil || m.api == nil {
		return Runtime{}, fmt.Errorf("%w: engine client is not configured", ErrEngineUnavailable)
	}
	if err := ValidateSpec(spec); err != nil {
		return Runtime{}, err
	}
	if spec.Workspace.Persistent {
		return Runtime{}, invalidSpec("persistent workspace creation is not enabled in this rollout item")
	}
	engine, err := m.EngineInfo(ctx)
	if err != nil {
		return Runtime{}, err
	}
	platform, err := parsePlatform(spec.Image.Platform)
	if err != nil {
		return Runtime{}, err
	}
	if engine.OperatingSys != platform[0] || engine.Architecture != platform[1] {
		return Runtime{}, fmt.Errorf("%w: engine %s/%s cannot create %s", ErrArchitectureMismatch, engine.OperatingSys, engine.Architecture, spec.Image.Platform)
	}
	if _, err := m.InspectLocalImage(ctx, spec.Image); err != nil {
		return Runtime{}, err
	}

	pinned, _ := pinnedImageReference(spec.Image)
	name := runtimeContainerName(spec.ID)
	labels := runtimeLabels(m.ownerID, spec)
	createResult, err := m.api.ContainerCreate(ctx, mobyclient.ContainerCreateOptions{
		Name:  name,
		Image: pinned,
		Platform: &ocispec.Platform{
			OS:           platform[0],
			Architecture: platform[1],
			Variant:      platform[2],
		},
		Config: &mobycontainer.Config{
			NetworkDisabled: true,
			WorkingDir:      "/workspace",
			Labels:          labels,
		},
		HostConfig: &mobycontainer.HostConfig{
			NetworkMode: mobycontainer.NetworkMode(NetworkNone),
		},
	})
	if err != nil {
		if containerderrdefs.IsConflict(err) {
			return Runtime{}, fmt.Errorf("%w: %s", ErrAlreadyExists, name)
		}
		return Runtime{}, fmt.Errorf("create runtime %s: %w", spec.ID, err)
	}

	runtime, verifyErr := m.verifyCreatedRuntime(ctx, spec, name, labels, createResult)
	if verifyErr == nil {
		return runtime, nil
	}
	_, cleanupErr := m.api.ContainerRemove(ctx, createResult.ID, mobyclient.ContainerRemoveOptions{Force: true, RemoveVolumes: false})
	if cleanupErr != nil {
		return Runtime{}, errors.Join(verifyErr, fmt.Errorf("rollback created runtime %s: %w", createResult.ID, cleanupErr))
	}
	return Runtime{}, verifyErr
}

func (m *DockerManager) verifyCreatedRuntime(ctx context.Context, spec RuntimeSpec, name string, expectedLabels map[string]string, createResult mobyclient.ContainerCreateResult) (Runtime, error) {
	if strings.TrimSpace(createResult.ID) == "" {
		return Runtime{}, fmt.Errorf("%w: engine returned an empty provider id", ErrRuntimeStateConflict)
	}
	result, err := m.api.ContainerInspect(ctx, createResult.ID, mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		return Runtime{}, fmt.Errorf("inspect created runtime %s: %w", createResult.ID, err)
	}
	actual := result.Container
	if actual.State == nil || actual.State.Running || actual.State.Status != mobycontainer.StateCreated {
		return Runtime{}, fmt.Errorf("%w: created runtime is not in created state", ErrRuntimeStateConflict)
	}
	if strings.TrimPrefix(actual.Name, "/") != name {
		return Runtime{}, fmt.Errorf("%w: engine returned name %q, expected %q", ErrRuntimeStateConflict, actual.Name, name)
	}
	if actual.Config == nil {
		return Runtime{}, fmt.Errorf("%w: created runtime has no configuration", ErrRuntimeStateConflict)
	}
	for key, expected := range expectedLabels {
		if actual.Config.Labels[key] != expected {
			return Runtime{}, fmt.Errorf("%w: created runtime label %s mismatch", ErrRuntimeStateConflict, key)
		}
	}
	if actual.HostConfig == nil || actual.HostConfig.NetworkMode != mobycontainer.NetworkMode(NetworkNone) || !actual.Config.NetworkDisabled {
		return Runtime{}, fmt.Errorf("%w: created runtime network is not disabled", ErrRuntimeStateConflict)
	}
	image, err := m.VerifyRuntimeImage(ctx, createResult.ID, spec.Image)
	if err != nil {
		return Runtime{}, err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, actual.Created)
	if err != nil {
		return Runtime{}, fmt.Errorf("%w: invalid engine creation time %q", ErrRuntimeStateConflict, actual.Created)
	}
	return Runtime{
		ID:             spec.ID,
		ConversationID: spec.ConversationID,
		ProviderID:     createResult.ID,
		Image:          image.Reference,
		Status:         StatusStopped,
		CreatedAt:      createdAt.UTC(),
		UpdatedAt:      createdAt.UTC(),
		Warnings:       append([]string(nil), createResult.Warnings...),
	}, nil
}

func runtimeContainerName(id RuntimeID) string {
	return "cyberstrike-agent-" + string(id)
}

func runtimeLabels(ownerID string, spec RuntimeSpec) map[string]string {
	return map[string]string{
		LabelManaged:        "true",
		LabelOwner:          ownerID,
		LabelRuntimeID:      string(spec.ID),
		LabelConversationID: spec.ConversationID,
		LabelResourceKind:   ResourceKindAgent,
		LabelImageDigest:    spec.Image.Digest,
		LabelImagePlatform:  spec.Image.Platform,
	}
}
