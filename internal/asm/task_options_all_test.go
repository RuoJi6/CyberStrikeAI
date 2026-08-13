package asm

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type allTaskOptionsTestAdapter struct {
	taskHistoryTestAdapter
	kinds  []string
	calls  []TaskOptionFilter
	errors map[string]error
}

func (a *allTaskOptionsTestAdapter) GetTaskProfile(context.Context, *Connection) (interface{}, error) {
	return map[string]interface{}{
		"provider":             ProviderXingRin,
		"dynamic_option_kinds": a.kinds,
	}, nil
}

func (a *allTaskOptionsTestAdapter) ListTaskOptions(_ context.Context, conn *Connection, filter TaskOptionFilter) (interface{}, error) {
	a.calls = append(a.calls, filter)
	if err := a.errors[filter.Kind]; err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderXingRin,
		"resource_id": conn.Resource.ID,
		"kind":        filter.Kind,
		"options": map[string]interface{}{
			"kind":      filter.Kind,
			"query":     filter.Query,
			"page":      filter.Page,
			"page_size": filter.PageSize,
		},
	}, nil
}

func TestListTaskOptionsAllAggregatesListKinds(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	adapter := &allTaskOptionsTestAdapter{
		kinds:  []string{"engines", "policy_detail", "wordlists", "nuclei_repositories", "engines"},
		errors: map[string]error{"wordlists": errors.New("wordlists unavailable")},
	}
	service.RegisterAdapter(adapter)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}

	profile, err := service.GetTaskProfile(context.Background(), resource.ID)
	if err != nil {
		t.Fatal(err)
	}
	profileMap := valueMap(profile)
	if !reflect.DeepEqual(profileMap["task_option_query_modes"], []string{"single", "all"}) {
		t.Fatalf("profile does not advertise all mode: %#v", profileMap)
	}

	value, err := service.ListTaskOptions(context.Background(), resource.ID, TaskOptionFilter{
		Kind: "ALL", Query: "needle", ID: "ignored", Page: 2, PageSize: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, ok := value.(AllTaskOptionsResult)
	if !ok {
		t.Fatalf("unexpected all result type: %T", value)
	}
	if !reflect.DeepEqual(result.SupportedKinds, []string{"engines", "policy_detail", "wordlists", "nuclei_repositories"}) {
		t.Fatalf("unexpected supported kinds: %#v", result.SupportedKinds)
	}
	if !reflect.DeepEqual(result.QueriedKinds, []string{"engines", "wordlists", "nuclei_repositories"}) {
		t.Fatalf("unexpected queried kinds: %#v", result.QueriedKinds)
	}
	if len(result.SkippedKinds) != 1 || result.SkippedKinds[0].Kind != "policy_detail" {
		t.Fatalf("unexpected skipped kinds: %#v", result.SkippedKinds)
	}
	if !result.Partial || result.Errors["wordlists"] == "" {
		t.Fatalf("partial error was not preserved: %#v", result)
	}
	if _, exists := result.Options["engines"]; !exists {
		t.Fatalf("engine options missing: %#v", result.Options)
	}
	if _, exists := result.Options["nuclei_repositories"]; !exists {
		t.Fatalf("repository options missing: %#v", result.Options)
	}
	if _, exists := result.Options["wordlists"]; exists {
		t.Fatalf("failed option kind should not have a payload: %#v", result.Options)
	}
	if len(adapter.calls) != 3 {
		t.Fatalf("unexpected upstream call count: %d", len(adapter.calls))
	}
	for _, call := range adapter.calls {
		if call.Kind == "all" || call.ID != "" || call.Query != "needle" || call.Page != 2 || call.PageSize != 7 {
			t.Fatalf("unexpected child filter: %#v", call)
		}
	}
}

func TestListTaskOptionsAllUsesNormalizedPagination(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	adapter := &allTaskOptionsTestAdapter{kinds: []string{"engines"}, errors: map[string]error{}}
	service.RegisterAdapter(adapter)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}

	value, err := service.ListTaskOptions(context.Background(), resource.ID, TaskOptionFilter{Kind: "all"})
	if err != nil {
		t.Fatal(err)
	}
	result := value.(AllTaskOptionsResult)
	if result.Page != 1 || result.PageSize != 20 || result.Partial || result.Errors != nil {
		t.Fatalf("unexpected normalized result: %#v", result)
	}
	if len(adapter.calls) != 1 || adapter.calls[0].Page != 1 || adapter.calls[0].PageSize != 20 {
		t.Fatalf("unexpected normalized child filter: %#v", adapter.calls)
	}
}
