package container

import (
	"context"
	"io"
	"strings"
	"testing"

	mobyclient "github.com/moby/moby/client"
)

type fakeDockerStatsAPI struct {
	payload string
	opts    mobyclient.ContainerStatsOptions
	id      string
}

func (f *fakeDockerStatsAPI) ContainerStats(_ context.Context, id string, opts mobyclient.ContainerStatsOptions) (mobyclient.ContainerStatsResult, error) {
	f.id = id
	f.opts = opts
	return mobyclient.ContainerStatsResult{Body: io.NopCloser(strings.NewReader(f.payload))}, nil
}

func TestReadContainerResourceUsageProjectsAggregateCounters(t *testing.T) {
	api := &fakeDockerStatsAPI{payload: `{
		"cpu_stats":{"cpu_usage":{"total_usage":500},"system_cpu_usage":2000,"online_cpus":2},
		"precpu_stats":{"cpu_usage":{"total_usage":300},"system_cpu_usage":1000},
		"memory_stats":{"usage":4096,"limit":8192},
		"pids_stats":{"current":7},
		"networks":{"eth0":{"rx_bytes":11,"tx_bytes":13},"eth1":{"rx_bytes":17,"tx_bytes":19}},
		"blkio_stats":{"io_service_bytes_recursive":[{"op":"Read","value":23},{"op":"Write","value":29}]}
	}`}
	usage, err := readContainerResourceUsage(context.Background(), api, "provider-safe")
	if err != nil {
		t.Fatal(err)
	}
	if api.id != "provider-safe" || api.opts.Stream || !api.opts.IncludePreviousSample {
		t.Fatalf("stats request = id=%q opts=%+v", api.id, api.opts)
	}
	if !usage.Available || usage.CPUPercent != 40 || usage.MemoryUsageBytes != 4096 || usage.MemoryLimitBytes != 8192 || usage.PIDs != 7 {
		t.Fatalf("core usage = %+v", usage)
	}
	if usage.NetworkRXBytes != 28 || usage.NetworkTXBytes != 32 || usage.BlockReadBytes != 23 || usage.BlockWriteBytes != 29 {
		t.Fatalf("aggregate usage = %+v", usage)
	}
}

func TestReadContainerResourceUsageDoesNotUnderflowCPUCounterReset(t *testing.T) {
	api := &fakeDockerStatsAPI{payload: `{
		"cpu_stats":{"cpu_usage":{"total_usage":10},"system_cpu_usage":20,"online_cpus":4},
		"precpu_stats":{"cpu_usage":{"total_usage":100},"system_cpu_usage":200}
	}`}
	usage, err := readContainerResourceUsage(context.Background(), api, "provider-reset")
	if err != nil {
		t.Fatal(err)
	}
	if usage.CPUPercent != 0 {
		t.Fatalf("counter reset produced cpu percent %f", usage.CPUPercent)
	}
}

func TestObservedPolicyDNSStatusFollowsGatewayAvailability(t *testing.T) {
	if got := observedPolicyDNSStatus(StatusStopped); got != string(StatusStopped) {
		t.Fatalf("stopped policy DNS status = %q", got)
	}
	if got := observedPolicyDNSStatus(StatusRunning); got != "ready" {
		t.Fatalf("running policy DNS status = %q", got)
	}
}
