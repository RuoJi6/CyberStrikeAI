package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestListContainerRuntimesUsesServerPaginationAndRBAC(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	for index := 0; index < 12; index++ {
		conversation, err := db.CreateConversation(fmt.Sprintf("container %02d", index), database.ConversationCreateMeta{
			RuntimeMode: database.ConversationRuntimeModeContainer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.AssignResourceToUser(user.ID, "conversation", conversation.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.CreateConversation("foreign container", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateConversation("assigned host", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeHost}); err != nil {
		t.Fatal(err)
	}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerInitializationProvider(db)

	response := performConversationRequest(user, http.MethodGet, "/api/container-runtimes?page=2&page_size=10&search=container&status=not_requested", nil, handler.ListContainerRuntimes)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Items      []map[string]interface{}             `json:"items"`
		Page       int                                  `json:"page"`
		PageSize   int                                  `json:"pageSize"`
		Total      int                                  `json:"total"`
		TotalPages int                                  `json:"totalPages"`
		Summary    database.ContainerRuntimeListSummary `json:"summary"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Page != 2 || payload.PageSize != 10 || payload.Total != 12 || payload.TotalPages != 2 || len(payload.Items) != 2 {
		t.Fatalf("payload = %#v", payload)
	}
	if payload.Summary.Total != 12 {
		t.Fatalf("summary = %#v", payload.Summary)
	}
	for _, item := range payload.Items {
		if item["runtimeMode"] != database.ConversationRuntimeModeContainer || item["status"] != "not_requested" {
			t.Fatalf("item = %#v", item)
		}
		for _, forbidden := range []string{"providerId", "spec", "observation"} {
			if _, ok := item[forbidden]; ok {
				t.Fatalf("item leaks %s: %#v", forbidden, item)
			}
		}
	}

	response = performConversationRequest(user, http.MethodGet, "/api/container-runtimes?page=1&page_size=25", nil, handler.ListContainerRuntimes)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid page size status = %d: %s", response.Code, response.Body.String())
	}
	response = performConversationRequest(user, http.MethodGet, "/api/container-runtimes?page=1&page_size=20&status=healthy", nil, handler.ListContainerRuntimes)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d: %s", response.Code, response.Body.String())
	}
}

func TestContainerRuntimeListOpenAPIContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/api/openapi/spec", nil)
	NewOpenAPIHandler(nil, zap.NewNop(), nil, nil).GetOpenAPISpec(context)
	if recorder.Code != http.StatusOK {
		t.Fatalf("openapi status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var document struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	var pathItem map[string]json.RawMessage
	if err := json.Unmarshal(document.Paths["/api/container-runtimes"], &pathItem); err != nil {
		t.Fatal(err)
	}
	var operation struct {
		Parameters []struct {
			Name   string `json:"name"`
			Schema struct {
				Enum []interface{} `json:"enum"`
			} `json:"schema"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(pathItem["get"], &operation); err != nil {
		t.Fatal(err)
	}
	if len(operation.Parameters) == 0 {
		t.Fatal("container runtime list OpenAPI path is missing")
	}
	enums := make(map[string][]interface{}, len(operation.Parameters))
	for _, parameter := range operation.Parameters {
		enums[parameter.Name] = parameter.Schema.Enum
	}
	if got := fmt.Sprint(enums["page_size"]); got != "[10 20 50 100]" {
		t.Fatalf("page_size enum = %s", got)
	}
	if got := fmt.Sprint(enums["status"]); got != "[all not_requested pending running stopped failed]" {
		t.Fatalf("status enum = %s", got)
	}
}
