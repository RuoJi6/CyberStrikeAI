package egresscontainer_test

import (
	"context"
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

//go:embed docker-network-integration.sh
var dockerNetworkIntegrationScript string

func TestDockerEgressNetworkAndBypassRegression(t *testing.T) {
	if os.Getenv("CYBERSTRIKE_EGRESS_DOCKER_INTEGRATION") != "1" {
		t.Skip("set CYBERSTRIKE_EGRESS_DOCKER_INTEGRATION=1 to run the real Docker network regression")
	}
	if os.Getenv("CYBERSTRIKE_EGRESS_IMAGE") == "" || os.Getenv("CYBERSTRIKE_AGENT_IMAGE") == "" {
		t.Fatal("CYBERSTRIKE_EGRESS_IMAGE and CYBERSTRIKE_AGENT_IMAGE are required")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("find docker CLI: %v", err)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Fatalf("find bash: %v", err)
	}

	scriptPath := filepath.Join(t.TempDir(), "docker-network-integration.sh")
	if err := os.WriteFile(scriptPath, []byte(dockerNetworkIntegrationScript), 0o700); err != nil {
		t.Fatalf("write embedded integration script: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", scriptPath)
	command.Env = append(os.Environ(), "CYBERSTRIKE_EGRESS_TEST_SUFFIX=go-"+time.Now().UTC().Format("150405.000000000"))
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("real Docker egress regression: %v\n%s", err, output)
	}
	if ctx.Err() != nil {
		t.Fatalf("real Docker egress regression timed out: %v\n%s", ctx.Err(), output)
	}
	t.Logf("real Docker egress regression passed:\n%s", output)
}
