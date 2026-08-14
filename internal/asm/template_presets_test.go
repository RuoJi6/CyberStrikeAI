package asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestBuiltInTemplatePresetsCoverBothNativeTemplateProviders(t *testing.T) {
	for _, provider := range []string{ProviderARL, ProviderScopeSentry} {
		presets := templatePresetsForProvider(provider)
		if len(presets) != 4 {
			t.Fatalf("provider %s presets=%d want=4", provider, len(presets))
		}
		if presets[0].ID != "quick_discovery" || presets[3].ID != "full_scan" {
			t.Fatalf("provider %s preset order=%#v", provider, presets)
		}
		for _, preset := range presets {
			if preset.ProviderOptions != nil {
				t.Fatal("public preset metadata must not expose the cross-provider option table")
			}
			if preset.Provider != provider || preset.ProviderConfig == nil || preset.MCPUsage == nil {
				t.Fatalf("public preset must expose current-provider decision data: %#v", preset)
			}
		}
	}
	if presets := templatePresetsForProvider(ProviderXingRin); len(presets) != 0 {
		t.Fatalf("XingRin must not advertise native templates: %#v", presets)
	}
}

func TestTemplatePresetDecisionDataDiffersByProvider(t *testing.T) {
	arl := templatePresetsForProvider(ProviderARL)[3]
	if arl.ProviderKind != "policy" || arl.ProviderConfig["port_scan_type"] != "all" || arl.ProviderConfig["poc_selection"] != "all" || arl.ProviderConfig["brute_selection"] != "all" {
		t.Fatalf("unexpected ARL decision data: %#v", arl)
	}
	if _, exists := arl.ProviderConfig["enabled_capabilities"]; exists {
		t.Fatalf("ARL preset must not expose ScopeSentry fields: %#v", arl.ProviderConfig)
	}
	scope := templatePresetsForProvider(ProviderScopeSentry)[3]
	if scope.ProviderKind != "task_template" || scope.ProviderConfig["ports"] != "1-65535" || scope.ProviderConfig["concurrency"] != float64(30) {
		t.Fatalf("unexpected ScopeSentry decision data: %#v", scope)
	}
	if _, exists := scope.ProviderConfig["port_scan_type"]; exists {
		t.Fatalf("ScopeSentry preset must not expose ARL fields: %#v", scope.ProviderConfig)
	}
}

func TestApplyTemplatePresetProducesFixedProviderNativeOptions(t *testing.T) {
	arl, err := applyTemplatePreset(ProviderARL, TemplateRequest{PresetID: "full_scan"})
	if err != nil {
		t.Fatal(err)
	}
	if arl.Name != "CyberStrikeAI · 全量扫描" || arl.Options["port_scan_type"] != "all" || arl.Options["nuclei_scan"] != true ||
		arl.Options["poc_selection"] != "all" || arl.Options["brute_selection"] != "all" {
		t.Fatalf("unexpected ARL preset: %#v", arl)
	}
	scope, err := applyTemplatePreset(ProviderScopeSentry, TemplateRequest{PresetID: "full_scan"})
	if err != nil {
		t.Fatal(err)
	}
	if scope.Options["ports"] != "1-65535" || scope.Options["concurrency"] != float64(30) {
		t.Fatalf("unexpected ScopeSentry preset: %#v", scope)
	}
	capabilities, ok := scope.Options["enabled_capabilities"].([]interface{})
	if !ok || len(capabilities) != len(scopeSentryRequiredCapabilities)-1 || strings.Contains(fmt.Sprint(capabilities), "passive_scan") {
		t.Fatalf("full ScopeSentry preset must assert every installed capability and omit unimplemented PassiveScan: %#v", scope.Options["enabled_capabilities"])
	}
}

func TestApplyTemplatePresetRejectsOverridesAndUnsupportedProviders(t *testing.T) {
	if _, err := applyTemplatePreset(ProviderARL, TemplateRequest{PresetID: "quick_discovery", Options: map[string]interface{}{"port_scan_type": "all"}}); err == nil {
		t.Fatal("built-in preset overrides must be rejected")
	}
	if _, err := applyTemplatePreset(ProviderXingRin, TemplateRequest{PresetID: "quick_discovery"}); err == nil {
		t.Fatal("XingRin must reject native template presets")
	}
	if _, err := applyTemplatePreset(ProviderARL, TemplateRequest{PresetID: "quick_discovery", Name: "renamed"}); err == nil {
		t.Fatal("preset rename must be rejected so creation stays idempotent")
	}
}
