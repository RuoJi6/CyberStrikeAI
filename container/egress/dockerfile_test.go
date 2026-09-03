package egresscontainer

import (
	"os"
	"strings"
	"testing"
)

func TestDockerfileUsesBuildKitTargetPlatform(t *testing.T) {
	raw, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}

	dockerfile := string(raw)
	if !strings.Contains(dockerfile, "ARG TARGETARCH\n") || !strings.Contains(dockerfile, "ARG TARGETOS\n") {
		t.Fatal("Dockerfile must consume BuildKit TARGETARCH and TARGETOS")
	}
	if strings.Contains(dockerfile, "ARG TARGETARCH=") || strings.Contains(dockerfile, "ARG TARGETOS=") {
		t.Fatal("Dockerfile must not override BuildKit target platform defaults")
	}
}
