package config

import (
	"strings"
	"testing"
)

func TestContainerRuntimeConfigDefaultsAndValidation(t *testing.T) {
	config := ContainerRuntimeConfig{
		Enabled:         true,
		OwnerID:         "deployment-01",
		ImageRepository: "ghcr.io/usestrix/strix-sandbox",
		ImageDigest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImagePlatform:   "linux/arm64",
	}
	config.applyDefaults()
	if err := config.validateEnabled(); err != nil {
		t.Fatal(err)
	}
	if config.InitializerWorkers != 2 || config.QueueCapacity != 64 || config.CreateTimeoutSeconds != 120 || config.MemoryBytes != 512<<20 || config.WorkspaceBytes != 1<<30 || config.LogMaxFiles != 3 {
		t.Fatalf("defaults = %#v", config)
	}
}

func TestContainerRuntimeConfigFailsClosedWhenEnabled(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ContainerRuntimeConfig)
		want   string
	}{
		{name: "owner", mutate: func(config *ContainerRuntimeConfig) { config.OwnerID = "" }, want: "owner_id"},
		{name: "digest", mutate: func(config *ContainerRuntimeConfig) { config.ImageDigest = "latest" }, want: "digest"},
		{name: "platform", mutate: func(config *ContainerRuntimeConfig) { config.ImagePlatform = "linux/aarch64" }, want: "canonical"},
		{name: "negative queue", mutate: func(config *ContainerRuntimeConfig) { config.QueueCapacity = -1 }, want: "queue_capacity"},
		{name: "nofile", mutate: func(config *ContainerRuntimeConfig) { config.NoFileSoft = 4096; config.NoFileHard = 1024 }, want: "nofile"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := ContainerRuntimeConfig{
				Enabled: true, OwnerID: "deployment-01",
				ImageRepository: "ghcr.io/usestrix/strix-sandbox",
				ImageDigest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ImagePlatform:   "linux/arm64",
			}
			config.applyDefaults()
			test.mutate(&config)
			err := config.validateEnabled()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
