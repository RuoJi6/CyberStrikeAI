package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

type probeResult struct {
	Engine         containerruntime.EngineInfo            `json:"engine"`
	Manifest       *containerruntime.ImageInspection      `json:"manifest,omitempty"`
	LocalImage     *containerruntime.ImageInspection      `json:"local_image,omitempty"`
	RuntimeImage   *containerruntime.ImageInspection      `json:"runtime_image,omitempty"`
	Initialization *containerruntime.InitializationRecord `json:"initialization,omitempty"`
	Created        *containerruntime.Runtime              `json:"created_runtime,omitempty"`
	Error          string                                 `json:"error,omitempty"`
}

func main() {
	os.Exit(run())
}

func run() int {
	repository := flag.String("repository", "", "image repository without tag or digest")
	digest := flag.String("digest", "", "expected sha256 manifest digest")
	platform := flag.String("platform", "", "expected linux platform")
	containerID := flag.String("container", "", "optional provider container ID to verify")
	createRuntimeID := flag.String("create-runtime-id", "", "diagnostic: create a stopped runtime with this system ID")
	conversationID := flag.String("conversation-id", "", "conversation ID for diagnostic runtime creation")
	ownerID := flag.String("owner-id", "", "control-plane owner ID for diagnostic runtime creation")
	backgroundCreate := flag.Bool("background-create", false, "create through the bounded asynchronous initializer")
	requiredPlatforms := flag.String("require-platforms", "", "comma-separated platforms required in the remote manifest")
	skipManifest := flag.Bool("skip-manifest", false, "diagnostic only: skip remote registry manifest inspection")
	timeout := flag.Duration("timeout", 20*time.Second, "overall probe timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var inspector containerruntime.RuntimeInspector
	var creator containerruntime.RuntimeCreator
	var closeInspector func() error
	if strings.TrimSpace(*createRuntimeID) != "" {
		manager, err := containerruntime.NewDockerManagerFromEnvironment(containerruntime.DockerManagerOptions{OwnerID: strings.TrimSpace(*ownerID)})
		if err != nil {
			return writeResult(probeResult{Error: err.Error()}, 1)
		}
		inspector = manager
		creator = manager
		closeInspector = manager.Close
	} else {
		dockerInspector, err := containerruntime.NewDockerInspectorFromEnvironment()
		if err != nil {
			return writeResult(probeResult{Error: err.Error()}, 1)
		}
		inspector = dockerInspector
		closeInspector = dockerInspector.Close
	}
	defer closeInspector()

	result := probeResult{}
	var err error
	result.Engine, err = inspector.EngineInfo(ctx)
	if err != nil {
		result.Error = err.Error()
		return writeResult(result, 1)
	}
	if strings.TrimSpace(*repository) == "" && strings.TrimSpace(*digest) == "" && strings.TrimSpace(*platform) == "" {
		return writeResult(result, 0)
	}

	image := containerruntime.ImageReference{
		Repository: strings.TrimSpace(*repository),
		Digest:     strings.TrimSpace(*digest),
		Platform:   strings.TrimSpace(*platform),
	}
	if !*skipManifest {
		inspection, inspectErr := inspector.InspectManifest(ctx, image)
		if inspectErr != nil {
			result.Error = inspectErr.Error()
			return writeResult(result, 1)
		}
		result.Manifest = &inspection
		required := splitPlatforms(*requiredPlatforms)
		if len(required) > 0 {
			if err := containerruntime.RequirePlatforms(inspection, required...); err != nil {
				result.Error = err.Error()
				return writeResult(result, 1)
			}
		}
	}

	local, err := inspector.InspectLocalImage(ctx, image)
	if err != nil {
		result.Error = err.Error()
		return writeResult(result, 1)
	}
	result.LocalImage = &local

	if strings.TrimSpace(*containerID) != "" {
		verified, verifyErr := inspector.VerifyRuntimeImage(ctx, strings.TrimSpace(*containerID), image)
		if verifyErr != nil {
			result.Error = verifyErr.Error()
			return writeResult(result, 1)
		}
		result.RuntimeImage = &verified
	}
	if creator != nil {
		spec := diagnosticRuntimeSpec(strings.TrimSpace(*createRuntimeID), strings.TrimSpace(*conversationID), image)
		if *backgroundCreate {
			store := newProbeInitializationStore()
			initializer, initializeErr := containerruntime.NewInitializer(creator, store, containerruntime.InitializerOptions{
				Workers:       1,
				QueueCapacity: 4,
				CreateTimeout: *timeout,
			})
			if initializeErr != nil {
				result.Error = initializeErr.Error()
				return writeResult(result, 1)
			}
			defer func() {
				closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer closeCancel()
				_ = initializer.Close(closeCtx)
			}()
			queued, ensureErr := initializer.EnsureAsync(ctx, spec)
			if ensureErr != nil {
				result.Initialization = &queued
				result.Error = ensureErr.Error()
				return writeResult(result, 1)
			}
			initialized, waitErr := waitForInitialization(ctx, initializer, spec.ConversationID)
			result.Initialization = &initialized
			if waitErr != nil {
				result.Error = waitErr.Error()
				return writeResult(result, 1)
			}
		} else {
			created, createErr := creator.Create(ctx, spec)
			if createErr != nil {
				result.Error = createErr.Error()
				return writeResult(result, 1)
			}
			result.Created = &created
		}
	}
	return writeResult(result, 0)
}

func waitForInitialization(ctx context.Context, initializer *containerruntime.Initializer, conversationID string) (containerruntime.InitializationRecord, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		record, err := initializer.Get(ctx, conversationID)
		if err != nil {
			return record, err
		}
		switch record.Status {
		case containerruntime.InitializationCreated:
			return record, nil
		case containerruntime.InitializationFailed:
			return record, fmt.Errorf("container initialization failed: %s", record.LastError)
		}
		select {
		case <-ctx.Done():
			return record, ctx.Err()
		case <-ticker.C:
		}
	}
}

func diagnosticRuntimeSpec(runtimeID, conversationID string, image containerruntime.ImageReference) containerruntime.RuntimeSpec {
	return containerruntime.RuntimeSpec{
		ID:             containerruntime.RuntimeID(runtimeID),
		ConversationID: conversationID,
		Image:          image,
		Resources: containerruntime.ResourceLimits{
			NanoCPUs:          250_000_000,
			MemoryBytes:       64 << 20,
			PIDs:              32,
			NoFileSoft:        256,
			NoFileHard:        512,
			WorkspaceBytes:    64 << 20,
			MaxConcurrentExec: 1,
			MaxQueuedExec:     4,
			LogMaxBytes:       4 << 20,
			LogMaxFiles:       2,
		},
		Security: containerruntime.SecurityProfile{
			ReadOnlyRootFS:      true,
			NoNewPrivileges:     true,
			DropAllCapabilities: true,
			NetworkMode:         containerruntime.NetworkNone,
			SeccompProfile:      "default",
			TmpfsBytes:          8 << 20,
		},
		Workspace: containerruntime.WorkspaceSpec{MountPath: "/workspace"},
	}
}

func splitPlatforms(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func writeResult(result probeResult, exitCode int) int {
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode probe result: %v\n", err)
		return 1
	}
	fmt.Println(string(encoded))
	return exitCode
}
