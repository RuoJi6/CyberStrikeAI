package traffictransform

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var requirementPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+$`)

// RunnerInventory is intentionally closed: a revision can only request a
// package that is already present in the reviewed runner image at this exact
// version. Runtime dependency downloads are never permitted.
type RunnerInventory map[string]string

func DefaultRunnerInventory() RunnerInventory {
	return RunnerInventory{
		"cryptography": "38.0.4",
	}
}

func PrepareRevision(revision Revision, inventory RunnerInventory) (Revision, ValidationReport) {
	revision.ProtocolVersion = strings.TrimSpace(revision.ProtocolVersion)
	if revision.ProtocolVersion == "" {
		revision.ProtocolVersion = ProtocolVersion
	}
	revision.Language = strings.TrimSpace(revision.Language)
	if revision.Language == "" {
		revision.Language = LanguagePython3
	}
	revision.Entrypoint = strings.TrimSpace(revision.Entrypoint)
	if revision.Entrypoint == "" {
		revision.Entrypoint = Entrypoint
	}
	revision.SDKVersion = strings.TrimSpace(revision.SDKVersion)
	if revision.SDKVersion == "" {
		revision.SDKVersion = SDKVersion
	}
	revision.SourceSHA256 = SourceDigest(revision.Source)

	report := ValidationReport{SourceSHA256: revision.SourceSHA256}
	addIssue := func(code, message string) {
		report.Issues = append(report.Issues, ValidationIssue{Code: code, Message: message})
	}
	if revision.ProtocolVersion != ProtocolVersion {
		addIssue("unsupported_protocol", "protocolVersion must be "+ProtocolVersion)
	}
	if revision.Language != LanguagePython3 {
		addIssue("unsupported_language", "language must be python3")
	}
	if revision.Entrypoint != Entrypoint {
		addIssue("invalid_entrypoint", "entrypoint must be transform.py")
	}
	if revision.SDKVersion != SDKVersion {
		addIssue("unsupported_sdk", "sdkVersion must be 1")
	}
	if len(revision.Source) == 0 {
		addIssue("source_empty", "transform source must not be empty")
	} else if len(revision.Source) > MaxSourceBytes {
		addIssue("source_too_large", fmt.Sprintf("transform source exceeds %d bytes", MaxSourceBytes))
	}
	canonicalHooks, err := CanonicalHooks(revision.Hooks)
	if err != nil {
		addIssue("invalid_hooks", err.Error())
	} else {
		revision.Hooks = canonicalHooks
		report.Hooks = append([]Hook(nil), canonicalHooks...)
		for _, hook := range canonicalHooks {
			needle := "def " + string(hook) + "("
			if !strings.Contains(revision.Source, needle) {
				addIssue("hook_missing", fmt.Sprintf("source does not declare %s", hook))
			}
		}
	}

	requirements, err := normalizeRequirements(revision.Requirements, inventory)
	if err != nil {
		addIssue("dependency_unavailable", err.Error())
	} else {
		revision.Requirements = requirements
	}
	report.Valid = len(report.Issues) == 0
	if report.Valid {
		// Static preparation alone is not enough to activate a revision. The
		// isolated runner must still parse and load the module successfully.
		revision.ValidationStatus = ValidationPending
	} else {
		revision.ValidationStatus = ValidationFailed
	}
	return revision, report
}

func normalizeRequirements(requirements []string, inventory RunnerInventory) ([]string, error) {
	seen := map[string]bool{}
	result := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		requirement = strings.TrimSpace(requirement)
		if requirement == "" {
			continue
		}
		if !requirementPattern.MatchString(requirement) {
			return nil, fmt.Errorf("requirement %q must pin one exact version", requirement)
		}
		parts := strings.SplitN(requirement, "==", 2)
		availableVersion, ok := inventory[strings.ToLower(parts[0])]
		if !ok || availableVersion != parts[1] {
			return nil, fmt.Errorf("requirement %q is not in the runner inventory", requirement)
		}
		canonical := strings.ToLower(parts[0]) + "==" + parts[1]
		if !seen[canonical] {
			seen[canonical] = true
			result = append(result, canonical)
		}
	}
	sort.Strings(result)
	return result, nil
}

func ValidateBinding(binding Binding, revision Revision) error {
	if err := ValidateBindingDraft(binding, revision); err != nil {
		return err
	}
	if binding.Mode == ModeInline && (strings.TrimSpace(binding.ApprovedByUserID) == "" || binding.ApprovedAt == nil) {
		return errors.New("inline binding requires explicit user approval")
	}
	return nil
}

func ValidateBindingDraft(binding Binding, revision Revision) error {
	if strings.TrimSpace(binding.ConversationID) == "" || strings.TrimSpace(binding.TransformID) == "" || strings.TrimSpace(binding.RevisionID) == "" {
		return errors.New("traffic transform binding identity is incomplete")
	}
	if binding.TransformID != revision.TransformID || binding.RevisionID != revision.ID {
		return errors.New("traffic transform binding revision mismatch")
	}
	if revision.ValidationStatus != ValidationPassed {
		return errors.New("traffic transform revision has not passed validation")
	}
	if binding.Mode != ModeObserve && binding.Mode != ModeInline {
		return errors.New("traffic transform binding mode must be observe or inline")
	}
	if binding.Mode == ModeObserve {
		if binding.FailurePolicy == "" {
			binding.FailurePolicy = FailurePolicyContinue
		}
		if binding.FailurePolicy != FailurePolicyContinue {
			return errors.New("observe binding failure policy must be continue")
		}
	}
	if binding.Mode == ModeInline {
		if binding.FailurePolicy != FailurePolicyClosed {
			return errors.New("inline binding failure policy must be closed")
		}
	}
	if binding.Priority < 0 || binding.Priority > 10000 {
		return errors.New("traffic transform binding priority is invalid")
	}
	matcher := binding.Matcher.Normalize()
	if encoded, err := json.Marshal(binding.Config); err != nil || len(encoded) > MaxStateJSONBytes {
		return errors.New("traffic transform binding config must be valid JSON within 64 KiB")
	}
	for _, scheme := range matcher.Schemes {
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("unsupported matcher scheme %q", scheme)
		}
	}
	for _, host := range matcher.Hosts {
		if strings.ContainsAny(host, "/?#:@\r\n\x00") {
			return fmt.Errorf("invalid matcher host %q", host)
		}
	}
	for _, method := range matcher.Methods {
		if strings.TrimSpace(method) == "" || strings.ContainsAny(method, " \t\r\n\x00") {
			return fmt.Errorf("invalid matcher method %q", method)
		}
	}
	for _, prefix := range matcher.PathPrefixes {
		if !strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "\r\n\x00") {
			return fmt.Errorf("invalid matcher path prefix %q", prefix)
		}
	}
	return nil
}
