package container

import (
	"context"
	"fmt"
	"sort"
	"strings"

	containerderrdefs "github.com/containerd/errdefs"
	"github.com/distribution/reference"
	mobyclient "github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type dockerInspectionAPI interface {
	Ping(context.Context, mobyclient.PingOptions) (mobyclient.PingResult, error)
	Info(context.Context, mobyclient.InfoOptions) (mobyclient.SystemInfoResult, error)
	DistributionInspect(context.Context, string, mobyclient.DistributionInspectOptions) (mobyclient.DistributionInspectResult, error)
	ImageInspect(context.Context, string, ...mobyclient.ImageInspectOption) (mobyclient.ImageInspectResult, error)
	ContainerInspect(context.Context, string, mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error)
}

// DockerInspector performs read-only checks through the official Moby Engine
// client. Lifecycle mutations are added separately after these checks are
// accepted, so this type intentionally does not implement RuntimeManager yet.
type DockerInspector struct {
	api    dockerInspectionAPI
	closer interface{ Close() error }
}

var _ RuntimeInspector = (*DockerInspector)(nil)

// NewDockerInspectorFromEnvironment honors Docker's standard DOCKER_HOST and
// TLS environment variables. API version negotiation is enabled by default by
// the current Moby client.
func NewDockerInspectorFromEnvironment() (*DockerInspector, error) {
	api, err := mobyclient.New(mobyclient.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize engine client: %v", ErrEngineUnavailable, err)
	}
	return &DockerInspector{api: api, closer: api}, nil
}

func newDockerInspector(api dockerInspectionAPI) *DockerInspector {
	return &DockerInspector{api: api}
}

func (d *DockerInspector) Close() error {
	if d == nil || d.closer == nil {
		return nil
	}
	return d.closer.Close()
}

func (d *DockerInspector) EngineInfo(ctx context.Context) (EngineInfo, error) {
	if d == nil || d.api == nil {
		return EngineInfo{}, fmt.Errorf("%w: engine client is not configured", ErrEngineUnavailable)
	}
	ping, err := d.api.Ping(ctx, mobyclient.PingOptions{NegotiateAPIVersion: true})
	if err != nil {
		return EngineInfo{}, fmt.Errorf("%w: ping: %v", ErrEngineUnavailable, err)
	}
	result, err := d.api.Info(ctx, mobyclient.InfoOptions{})
	if err != nil {
		return EngineInfo{}, fmt.Errorf("%w: info: %v", ErrEngineUnavailable, err)
	}
	info := result.Info
	return EngineInfo{
		Available:       true,
		Version:         info.ServerVersion,
		APIVersion:      ping.APIVersion,
		Architecture:    info.Architecture,
		OperatingSys:    info.OSType,
		CgroupVersion:   info.CgroupVersion,
		SecurityOptions: append([]string(nil), info.SecurityOptions...),
	}, nil
}

func (d *DockerInspector) InspectManifest(ctx context.Context, image ImageReference) (ImageInspection, error) {
	if d == nil || d.api == nil {
		return ImageInspection{}, fmt.Errorf("%w: engine client is not configured", ErrEngineUnavailable)
	}
	pinned, err := pinnedImageReference(image)
	if err != nil {
		return ImageInspection{}, err
	}
	result, err := d.api.DistributionInspect(ctx, pinned, mobyclient.DistributionInspectOptions{})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return ImageInspection{}, fmt.Errorf("%w: manifest %s", ErrNotFound, pinned)
		}
		return ImageInspection{}, fmt.Errorf("%w: inspect %s: %v", ErrRegistryUnavailable, pinned, err)
	}
	resolved := result.Descriptor.Digest.String()
	if resolved != image.Digest {
		return ImageInspection{}, fmt.Errorf("%w: expected %s, got %s", ErrImageDigestMismatch, image.Digest, resolved)
	}
	platforms := normalizedPlatforms(result.Platforms)
	inspection := ImageInspection{
		Reference:      resolvedReference(image),
		ManifestDigest: resolved,
		Platforms:      platforms,
	}
	if err := RequirePlatforms(inspection, image.Platform); err != nil {
		return ImageInspection{}, err
	}
	return inspection, nil
}

func (d *DockerInspector) InspectLocalImage(ctx context.Context, image ImageReference) (ImageInspection, error) {
	if d == nil || d.api == nil {
		return ImageInspection{}, fmt.Errorf("%w: engine client is not configured", ErrEngineUnavailable)
	}
	pinned, err := pinnedImageReference(image)
	if err != nil {
		return ImageInspection{}, err
	}
	result, err := d.api.ImageInspect(ctx, pinned)
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return ImageInspection{}, fmt.Errorf("%w: local image %s", ErrNotFound, pinned)
		}
		return ImageInspection{}, fmt.Errorf("inspect local image %s: %w", pinned, err)
	}
	return imageInspectionFromLocal(result, image)
}

func (d *DockerInspector) VerifyRuntimeImage(ctx context.Context, providerID string, image ImageReference) (ImageInspection, error) {
	if d == nil || d.api == nil {
		return ImageInspection{}, fmt.Errorf("%w: engine client is not configured", ErrEngineUnavailable)
	}
	pinned, err := pinnedImageReference(image)
	if err != nil {
		return ImageInspection{}, err
	}
	if strings.TrimSpace(providerID) == "" {
		return ImageInspection{}, invalidSpec("provider id is required")
	}
	result, err := d.api.ContainerInspect(ctx, providerID, mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return ImageInspection{}, fmt.Errorf("%w: provider runtime %s", ErrNotFound, providerID)
		}
		return ImageInspection{}, fmt.Errorf("inspect provider runtime %s: %w", providerID, err)
	}
	if result.Container.Config == nil {
		return ImageInspection{}, fmt.Errorf("%w: runtime has no image configuration", ErrImageDigestMismatch)
	}
	configured, err := normalizePinnedReference(result.Container.Config.Image)
	if err != nil || configured != pinned {
		return ImageInspection{}, fmt.Errorf("%w: runtime configured %q, expected %q", ErrImageDigestMismatch, result.Container.Config.Image, pinned)
	}
	local, err := d.api.ImageInspect(ctx, result.Container.Image)
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return ImageInspection{}, fmt.Errorf("%w: runtime image %s", ErrNotFound, result.Container.Image)
		}
		return ImageInspection{}, fmt.Errorf("inspect runtime image %s: %w", result.Container.Image, err)
	}
	return imageInspectionFromLocal(local, image)
}

func imageInspectionFromLocal(result mobyclient.ImageInspectResult, expected ImageReference) (ImageInspection, error) {
	if !containsDigest(result.RepoDigests, expected.Digest) {
		return ImageInspection{}, fmt.Errorf("%w: local image does not reference %s", ErrImageDigestMismatch, expected.Digest)
	}
	actualPlatform := platformString(ocispec.Platform{
		OS:           result.Os,
		Architecture: result.Architecture,
		Variant:      result.Variant,
	})
	inspection := ImageInspection{
		Reference:      resolvedReference(expected),
		ManifestDigest: expected.Digest,
		Platforms:      []string{actualPlatform},
		ImageID:        result.ID,
		SizeBytes:      result.Size,
		Local:          true,
	}
	if err := RequirePlatforms(inspection, expected.Platform); err != nil {
		return ImageInspection{}, err
	}
	return inspection, nil
}

// RequirePlatforms verifies that every requested platform exists. A required
// platform without a variant accepts any matching variant from the manifest.
func RequirePlatforms(inspection ImageInspection, required ...string) error {
	for _, wanted := range required {
		wantedParts, err := parsePlatform(wanted)
		if err != nil {
			return err
		}
		matched := false
		for _, available := range inspection.Platforms {
			availableParts, parseErr := parsePlatform(available)
			if parseErr != nil {
				continue
			}
			if wantedParts[0] == availableParts[0] && wantedParts[1] == availableParts[1] && (wantedParts[2] == "" || wantedParts[2] == availableParts[2]) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%w: required %s, available %s", ErrArchitectureMismatch, wanted, strings.Join(inspection.Platforms, ","))
		}
	}
	return nil
}

func pinnedImageReference(image ImageReference) (string, error) {
	if err := ValidateImageReference(image); err != nil {
		return "", err
	}
	named, _ := reference.ParseNormalizedNamed(image.Repository)
	return named.Name() + "@" + image.Digest, nil
}

func normalizePinnedReference(value string) (string, error) {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	digested, ok := named.(reference.Digested)
	if !ok {
		return "", fmt.Errorf("image reference is not digest-pinned")
	}
	return reference.TrimNamed(named).Name() + "@" + digested.Digest().String(), nil
}

func resolvedReference(image ImageReference) ImageReference {
	resolved := image
	resolved.ResolvedDigest = image.Digest
	return resolved
}

func normalizedPlatforms(platforms []ocispec.Platform) []string {
	set := make(map[string]struct{}, len(platforms))
	for _, platform := range platforms {
		value := platformString(platform)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func platformString(platform ocispec.Platform) string {
	if platform.OS == "" || platform.Architecture == "" {
		return ""
	}
	value := platform.OS + "/" + platform.Architecture
	if platform.Variant != "" {
		value += "/" + platform.Variant
	}
	return value
}

func containsDigest(repoDigests []string, expected string) bool {
	for _, repoDigest := range repoDigests {
		separator := strings.LastIndex(repoDigest, "@")
		if separator >= 0 && repoDigest[separator+1:] == expected {
			return true
		}
	}
	return false
}
