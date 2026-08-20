package container

import (
	"context"
	"errors"
	"testing"

	mobycontainer "github.com/moby/moby/api/types/container"
	mobyimage "github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/api/types/system"
	mobyclient "github.com/moby/moby/client"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type fakeDockerInspectionAPI struct {
	pingResult         mobyclient.PingResult
	pingErr            error
	infoResult         mobyclient.SystemInfoResult
	infoErr            error
	distributionResult mobyclient.DistributionInspectResult
	distributionErr    error
	imageResult        mobyclient.ImageInspectResult
	imageErr           error
	containerResult    mobyclient.ContainerInspectResult
	containerErr       error
	distributionRef    string
	imageRef           string
	containerID        string
}

func (f *fakeDockerInspectionAPI) Ping(context.Context, mobyclient.PingOptions) (mobyclient.PingResult, error) {
	return f.pingResult, f.pingErr
}

func (f *fakeDockerInspectionAPI) Info(context.Context, mobyclient.InfoOptions) (mobyclient.SystemInfoResult, error) {
	return f.infoResult, f.infoErr
}

func (f *fakeDockerInspectionAPI) DistributionInspect(_ context.Context, ref string, _ mobyclient.DistributionInspectOptions) (mobyclient.DistributionInspectResult, error) {
	f.distributionRef = ref
	return f.distributionResult, f.distributionErr
}

func (f *fakeDockerInspectionAPI) ImageInspect(_ context.Context, ref string, _ ...mobyclient.ImageInspectOption) (mobyclient.ImageInspectResult, error) {
	f.imageRef = ref
	return f.imageResult, f.imageErr
}

func (f *fakeDockerInspectionAPI) ContainerInspect(_ context.Context, id string, _ mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error) {
	f.containerID = id
	return f.containerResult, f.containerErr
}

func TestDockerInspectorEngineInfo(t *testing.T) {
	api := &fakeDockerInspectionAPI{
		pingResult: mobyclient.PingResult{APIVersion: "1.52", OSType: "linux"},
		infoResult: mobyclient.SystemInfoResult{Info: system.Info{
			ServerVersion:   "29.1.3",
			Architecture:    "arm64",
			OSType:          "linux",
			CgroupVersion:   "2",
			SecurityOptions: []string{"name=apparmor", "name=seccomp,profile=builtin"},
		}},
	}
	inspector := newDockerInspector(api)
	info, err := inspector.EngineInfo(context.Background())
	if err != nil {
		t.Fatalf("engine info: %v", err)
	}
	if !info.Available || info.Version != "29.1.3" || info.APIVersion != "1.52" || info.Architecture != "arm64" || info.CgroupVersion != "2" {
		t.Fatalf("engine info = %#v", info)
	}
}

func TestDockerInspectorEngineInfoFailsClosed(t *testing.T) {
	api := &fakeDockerInspectionAPI{pingErr: errors.New("socket unavailable")}
	_, err := newDockerInspector(api).EngineInfo(context.Background())
	if !errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("engine error = %v", err)
	}
}

func TestDockerInspectorManifestDigestAndPlatforms(t *testing.T) {
	image := inspectionImageReference()
	api := &fakeDockerInspectionAPI{
		distributionResult: mobyclient.DistributionInspectResult{DistributionInspect: registry.DistributionInspect{
			Descriptor: ocispec.Descriptor{Digest: digest.Digest(image.Digest)},
			Platforms: []ocispec.Platform{
				{OS: "linux", Architecture: "amd64"},
				{OS: "linux", Architecture: "arm64", Variant: "v8"},
				{OS: "unknown", Architecture: "unknown"},
			},
		}},
	}
	inspection, err := newDockerInspector(api).InspectManifest(context.Background(), image)
	if err != nil {
		t.Fatalf("inspect manifest: %v", err)
	}
	if api.distributionRef != "docker.io/library/alpine@"+image.Digest {
		t.Fatalf("distribution ref = %q", api.distributionRef)
	}
	if inspection.ManifestDigest != image.Digest || inspection.Reference.ResolvedDigest != image.Digest || inspection.Local {
		t.Fatalf("inspection = %#v", inspection)
	}
	if err := RequirePlatforms(inspection, "linux/amd64", "linux/arm64"); err != nil {
		t.Fatalf("multi-platform requirement: %v", err)
	}
	if err := RequirePlatforms(inspection, "linux/s390x"); !errors.Is(err, ErrArchitectureMismatch) {
		t.Fatalf("missing platform error = %v", err)
	}
}

func TestDockerInspectorRejectsManifestDigestMismatch(t *testing.T) {
	image := inspectionImageReference()
	api := &fakeDockerInspectionAPI{
		distributionResult: mobyclient.DistributionInspectResult{DistributionInspect: registry.DistributionInspect{
			Descriptor: ocispec.Descriptor{Digest: digest.Digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
			Platforms:  []ocispec.Platform{{OS: "linux", Architecture: "arm64"}},
		}},
	}
	_, err := newDockerInspector(api).InspectManifest(context.Background(), image)
	if !errors.Is(err, ErrImageDigestMismatch) {
		t.Fatalf("digest mismatch = %v", err)
	}
}

func TestDockerInspectorLocalAndRuntimeImage(t *testing.T) {
	image := inspectionImageReference()
	api := &fakeDockerInspectionAPI{
		imageResult: mobyclient.ImageInspectResult{InspectResponse: mobyimage.InspectResponse{
			ID:           "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			RepoDigests:  []string{"alpine@" + image.Digest},
			Architecture: "arm64",
			Variant:      "v8",
			Os:           "linux",
			Size:         13 << 20,
		}},
		containerResult: mobyclient.ContainerInspectResult{Container: mobycontainer.InspectResponse{
			ID:     "provider-1",
			Image:  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			Config: &mobycontainer.Config{Image: "alpine@" + image.Digest},
		}},
	}
	inspector := newDockerInspector(api)
	local, err := inspector.InspectLocalImage(context.Background(), image)
	if err != nil {
		t.Fatalf("inspect local image: %v", err)
	}
	if !local.Local || local.ImageID == "" || local.Reference.ResolvedDigest != image.Digest {
		t.Fatalf("local inspection = %#v", local)
	}

	verified, err := inspector.VerifyRuntimeImage(context.Background(), "provider-1", image)
	if err != nil {
		t.Fatalf("verify runtime image: %v", err)
	}
	if api.containerID != "provider-1" || api.imageRef != api.containerResult.Container.Image || verified.ImageID != local.ImageID {
		t.Fatalf("verified = %#v, container id = %q, image ref = %q", verified, api.containerID, api.imageRef)
	}
}

func TestDockerInspectorRejectsRuntimeConfiguredWithTag(t *testing.T) {
	image := inspectionImageReference()
	api := &fakeDockerInspectionAPI{
		containerResult: mobyclient.ContainerInspectResult{Container: mobycontainer.InspectResponse{
			ID:     "provider-1",
			Image:  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			Config: &mobycontainer.Config{Image: "alpine:3.22"},
		}},
	}
	_, err := newDockerInspector(api).VerifyRuntimeImage(context.Background(), "provider-1", image)
	if !errors.Is(err, ErrImageDigestMismatch) {
		t.Fatalf("tagged runtime error = %v", err)
	}
}

func inspectionImageReference() ImageReference {
	return ImageReference{
		Repository: "alpine",
		Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Platform:   "linux/arm64",
	}
}
