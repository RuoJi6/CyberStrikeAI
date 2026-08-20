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
	Engine       containerruntime.EngineInfo       `json:"engine"`
	Manifest     *containerruntime.ImageInspection `json:"manifest,omitempty"`
	LocalImage   *containerruntime.ImageInspection `json:"local_image,omitempty"`
	RuntimeImage *containerruntime.ImageInspection `json:"runtime_image,omitempty"`
	Error        string                            `json:"error,omitempty"`
}

func main() {
	os.Exit(run())
}

func run() int {
	repository := flag.String("repository", "", "image repository without tag or digest")
	digest := flag.String("digest", "", "expected sha256 manifest digest")
	platform := flag.String("platform", "", "expected linux platform")
	containerID := flag.String("container", "", "optional provider container ID to verify")
	requiredPlatforms := flag.String("require-platforms", "", "comma-separated platforms required in the remote manifest")
	skipManifest := flag.Bool("skip-manifest", false, "diagnostic only: skip remote registry manifest inspection")
	timeout := flag.Duration("timeout", 20*time.Second, "overall probe timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	inspector, err := containerruntime.NewDockerInspectorFromEnvironment()
	if err != nil {
		return writeResult(probeResult{Error: err.Error()}, 1)
	}
	defer inspector.Close()

	result := probeResult{}
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
	return writeResult(result, 0)
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
