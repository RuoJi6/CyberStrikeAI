package container

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/distribution/reference"
)

var sha256DigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var snapshotIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var generatedNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var authProfilesVersionPattern = regexp.MustCompile(`^[a-f0-9]{16}$`)

// ValidateSpec rejects ambiguous or unsafe runtime requests before an engine
// implementation sees them.
func ValidateSpec(spec RuntimeSpec) error {
	if strings.TrimSpace(string(spec.ID)) == "" {
		return invalidSpec("runtime id is required")
	}
	if !generatedNamePattern.MatchString(string(spec.ID)) {
		return invalidSpec("runtime id contains unsupported characters")
	}
	if strings.TrimSpace(spec.ConversationID) == "" {
		return invalidSpec("conversation id is required")
	}
	if !generatedNamePattern.MatchString(spec.ConversationID) {
		return invalidSpec("conversation id contains unsupported characters")
	}
	if err := ValidateImageReference(spec.Image); err != nil {
		return err
	}
	if spec.Resources.NanoCPUs <= 0 || spec.Resources.MemoryBytes <= 0 || spec.Resources.PIDs <= 0 {
		return invalidSpec("cpu, memory and pid limits must be positive")
	}
	if spec.Resources.NoFileSoft == 0 || spec.Resources.NoFileHard == 0 || spec.Resources.NoFileSoft > spec.Resources.NoFileHard {
		return invalidSpec("nofile limits must be positive and ordered")
	}
	if spec.Resources.NoFileHard > math.MaxInt64 {
		return invalidSpec("nofile limits exceed the engine range")
	}
	if spec.Resources.WorkspaceBytes <= 0 || spec.Resources.MaxConcurrentExec <= 0 || spec.Resources.MaxQueuedExec <= 0 {
		return invalidSpec("workspace, exec concurrency and exec queue limits must be positive")
	}
	if spec.Resources.LogMaxBytes <= 0 || spec.Resources.LogMaxFiles <= 0 {
		return invalidSpec("container log rotation limits must be positive")
	}
	if !spec.Security.ReadOnlyRootFS || !spec.Security.NoNewPrivileges || !spec.Security.DropAllCapabilities {
		return invalidSpec("read-only rootfs, no-new-privileges and capability drop are required")
	}
	if spec.Security.NetworkMode != NetworkNone && spec.Security.NetworkMode != NetworkInternal {
		return invalidSpec("runtime network mode must be none or internal")
	}
	if spec.Security.TmpfsBytes <= 0 {
		return invalidSpec("tmpfs limit must be positive")
	}
	if strings.TrimSpace(spec.Security.SeccompProfile) != "default" {
		return invalidSpec("runtimes require the Docker default seccomp profile")
	}
	if spec.Workspace.MountPath != "/workspace" {
		return invalidSpec("workspace mount path must be /workspace")
	}
	if spec.Workspace.Persistent && strings.TrimSpace(spec.Workspace.VolumeName) == "" {
		return invalidSpec("persistent workspace requires a named volume")
	}
	if spec.Workspace.Persistent && spec.Workspace.VolumeName != WorkspaceVolumeName(spec.ID) {
		return invalidSpec("persistent workspace volume name must be derived from the runtime id")
	}
	if !spec.Workspace.Persistent && strings.TrimSpace(spec.Workspace.VolumeName) != "" {
		return invalidSpec("ephemeral workspace cannot declare a named volume")
	}
	if err := ValidateReadinessPolicy(spec.Readiness, spec.Image); err != nil {
		return err
	}
	if spec.EgressGateway != nil {
		if spec.Security.NetworkMode != NetworkInternal {
			return invalidSpec("egress gateway requires the per-conversation internal network")
		}
		if err := ValidateEgressGatewaySpec(*spec.EgressGateway); err != nil {
			return err
		}
		if spec.EgressGateway.UpstreamRoute != nil && spec.EgressGateway.UpstreamRoute.ID != spec.ConversationID {
			return invalidSpec("egress gateway upstream route must be bound to the conversation")
		}
	}
	return nil
}

// ValidateEgressGatewaySpec rejects an unpinned or effectively unlimited
// gateway before any Docker resource is created.
func ValidateEgressGatewaySpec(spec EgressGatewaySpec) error {
	if err := ValidateImageReference(spec.Image); err != nil {
		return fmt.Errorf("egress gateway: %w", err)
	}
	resources := spec.Resources
	if resources.NanoCPUs <= 0 || resources.MemoryBytes <= 0 || resources.PIDs <= 0 {
		return invalidSpec("egress gateway cpu, memory and pid limits must be positive")
	}
	if resources.NoFileSoft == 0 || resources.NoFileHard == 0 || resources.NoFileSoft > resources.NoFileHard || resources.NoFileHard > math.MaxInt64 {
		return invalidSpec("egress gateway nofile limits must be positive, ordered and within engine range")
	}
	if resources.TmpfsBytes <= 0 || resources.LogMaxBytes <= 0 || resources.LogMaxFiles <= 0 {
		return invalidSpec("egress gateway tmpfs and log rotation limits must be positive")
	}
	if spec.BoundarySnapshot != nil {
		id := strings.TrimSpace(spec.BoundarySnapshot.ID)
		if id != spec.BoundarySnapshot.ID || !snapshotIDPattern.MatchString(id) {
			return invalidSpec("egress gateway boundary snapshot id must be a canonical UUID")
		}
		digest := strings.TrimSpace(spec.BoundarySnapshot.SHA256)
		if digest != spec.BoundarySnapshot.SHA256 || !sha256DigestPattern.MatchString(digest) {
			return invalidSpec("egress gateway boundary snapshot digest must be a lowercase sha256 digest")
		}
	}
	if spec.UpstreamRoute != nil {
		id := strings.TrimSpace(spec.UpstreamRoute.ID)
		if id != spec.UpstreamRoute.ID || !generatedNamePattern.MatchString(id) {
			return invalidSpec("egress gateway upstream route id must be canonical and label-safe")
		}
		digest := strings.TrimSpace(spec.UpstreamRoute.SHA256)
		if digest != spec.UpstreamRoute.SHA256 || !sha256DigestPattern.MatchString(digest) {
			return invalidSpec("egress gateway upstream route digest must be a lowercase sha256 digest")
		}
		if spec.BoundarySnapshot == nil {
			return invalidSpec("egress gateway upstream route requires a boundary snapshot")
		}
	}
	if spec.AuthProfiles != nil {
		id := strings.TrimSpace(spec.AuthProfiles.ID)
		if id != spec.AuthProfiles.ID || !generatedNamePattern.MatchString(id) {
			return invalidSpec("egress gateway auth profiles id must be canonical and label-safe")
		}
		digest := strings.TrimSpace(spec.AuthProfiles.SHA256)
		if digest != spec.AuthProfiles.SHA256 || !sha256DigestPattern.MatchString(digest) {
			return invalidSpec("egress gateway auth profiles digest must be a lowercase sha256 digest")
		}
		if spec.BoundarySnapshot == nil {
			return invalidSpec("egress gateway auth profiles require a boundary snapshot")
		}
		prefix := "auth-" + spec.BoundarySnapshot.ID + "-"
		version := strings.TrimPrefix(id, prefix)
		if version == id || !authProfilesVersionPattern.MatchString(version) {
			return invalidSpec("egress gateway auth profiles must be bound to the boundary snapshot")
		}
	}
	return nil
}

// ValidateImageReference requires a repository without a tag, an immutable
// digest and an explicit linux platform. The repository parser normalizes
// familiar Docker Hub names while rejecting tag/digest smuggling.
func ValidateImageReference(image ImageReference) error {
	repository := strings.TrimSpace(image.Repository)
	if repository == "" {
		return invalidSpec("image repository is required")
	}
	named, err := reference.ParseNormalizedNamed(repository)
	if err != nil {
		return invalidSpec("image repository is invalid")
	}
	if _, tagged := named.(reference.Tagged); tagged {
		return invalidSpec("image repository must not include a tag")
	}
	if _, digested := named.(reference.Digested); digested {
		return invalidSpec("image repository must not include a digest")
	}
	if !sha256DigestPattern.MatchString(image.Digest) {
		return invalidSpec("image digest must be a lowercase sha256 digest")
	}
	if strings.TrimSpace(image.ResolvedDigest) != "" {
		return invalidSpec("resolved image digest is engine output and cannot be requested")
	}
	parsedPlatform, err := parsePlatform(image.Platform)
	if err != nil {
		return err
	}
	if strings.TrimSpace(image.Platform) != platformFromParts(parsedPlatform) {
		return invalidSpec("image platform must use canonical OCI architecture names")
	}
	return nil
}

func parsePlatform(platform string) ([3]string, error) {
	parts := strings.Split(strings.TrimSpace(platform), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "linux" || parts[1] == "" {
		return [3]string{}, invalidSpec("image platform must be linux/<architecture>[/<variant>]")
	}
	if len(parts) == 3 && parts[2] == "" {
		return [3]string{}, invalidSpec("image platform variant cannot be empty")
	}
	parsed := [3]string{parts[0], normalizeArchitecture(parts[1]), ""}
	if len(parts) == 3 {
		parsed[2] = parts[2]
	}
	return parsed, nil
}

func normalizeArchitecture(architecture string) string {
	switch strings.ToLower(strings.TrimSpace(architecture)) {
	case "aarch64", "arm64":
		return "arm64"
	case "x86_64", "x86-64", "amd64":
		return "amd64"
	default:
		return strings.ToLower(strings.TrimSpace(architecture))
	}
}

func platformFromParts(parts [3]string) string {
	value := parts[0] + "/" + parts[1]
	if parts[2] != "" {
		value += "/" + parts[2]
	}
	return value
}

func invalidSpec(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpecification, message)
}

// IsNotFound allows callers to classify provider-specific wrapped errors.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}
