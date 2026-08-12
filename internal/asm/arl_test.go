package asm

import (
	"errors"
	"reflect"
	"testing"
)

func TestBuildARLTaskRequestModes(t *testing.T) {
	endpoint, body, err := buildARLTaskRequest(TaskRequest{
		Name: "direct", Target: "192.0.2.10",
		Options: map[string]interface{}{"task_mode": "direct", "port_scan": true, "port_scan_type": "top100", "site_capture": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "/api/task/" || body["port_scan_type"] != "top100" || body["site_capture"] != true {
		t.Fatalf("unexpected direct request: endpoint=%s body=%#v", endpoint, body)
	}
	const policyID = "64b000000000000000000001"
	endpoint, body, err = buildARLTaskRequest(TaskRequest{
		Name: "policy", Target: "192.0.2.11",
		Options: map[string]interface{}{"task_mode": "policy", "policy_id": policyID, "task_tag": "risk_cruising"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "/api/task/policy/" || body["policy_id"] != policyID || body["task_tag"] != "risk_cruising" {
		t.Fatalf("unexpected policy request: endpoint=%s body=%#v", endpoint, body)
	}
	for name, request := range map[string]TaskRequest{
		"direct rejects custom ports": {Target: "192.0.2.10", Options: map[string]interface{}{"port_custom": "80,443"}},
		"policy requires id":          {Target: "192.0.2.10", Options: map[string]interface{}{"task_mode": "policy"}},
		"direct rejects custom enum":  {Target: "192.0.2.10", Options: map[string]interface{}{"port_scan_type": "custom"}},
		"strict boolean":              {Target: "192.0.2.10", Options: map[string]interface{}{"port_scan": "yes"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := buildARLTaskRequest(request); err == nil {
				t.Fatal("expected invalid ARL request to fail")
			}
		})
	}
}

func TestARLAlreadyFinishedStopErrorIsTyped(t *testing.T) {
	err := arlResponseError(map[string]interface{}{"code": 105, "message": "任务已经完成"})
	var apiErr *arlAPIError
	if !errors.As(err, &apiErr) || apiErr.Code != "105" || apiErr.Message != "任务已经完成" {
		t.Fatalf("unexpected typed ARL error: %#v", err)
	}
}

func TestARLResultTypesMatchUpstreamTaskDetailCollections(t *testing.T) {
	want := []string{"site", "domain", "ip", "cert", "service", "fileleak", "url", "vulnerability", "npoc_service", "cip", "nuclei_result", "stat_finger", "wih"}
	got := make([]string, 0, len(want))
	for _, item := range providerResultTypes(ProviderARL) {
		got = append(got, item.ID)
		if _, ok := arlAssetEndpoints[item.ID]; !ok {
			t.Fatalf("ARL result type %q has no endpoint", item.ID)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ARL result types=%v want=%v", got, want)
	}
}

func TestARLPipelineProgressUsesCompletedStages(t *testing.T) {
	task := map[string]interface{}{
		"service": []interface{}{map[string]interface{}{"name": "port_scan"}, map[string]interface{}{"name": "ssl_cert"}},
		"options": map[string]interface{}{"port_scan": true, "ssl_cert": true, "site_identify": true, "file_leak": true},
	}
	progress := arlPipelineProgress(task)
	if progress <= 0 || progress >= 100 {
		t.Fatalf("unexpected running progress: %d", progress)
	}
	if stage := arlPipelineStage(map[string]interface{}{"status": "file_leak"}); stage != "file_leak" {
		t.Fatalf("unexpected ARL stage: %s", stage)
	}
}

func TestProviderResultTypeValidationIsProviderSpecific(t *testing.T) {
	if !providerSupportsResultType(ProviderARL, "nuclei_result") {
		t.Fatal("ARL should expose nuclei_result")
	}
	if providerSupportsResultType(ProviderXingRin, "nuclei_result") || providerSupportsResultType(ProviderScopeSentry, "cert") {
		t.Fatal("provider-specific ARL result collections leaked to other adapters")
	}
}
