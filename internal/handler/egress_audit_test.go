package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestEgressAuditHandlerListsGetsAndExportsSafeProjection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, eventID := newEgressAuditHandlerFixture(t)
	handler := NewEgressAuditHandler(db)

	listRecorder := httptest.NewRecorder()
	list := egressAuditTestContext(listRecorder, http.MethodGet, "/api/egress-audit-events?page=1&page_size=10&q=allowed.example&category=network&event_type=http&decision=allowed")
	handler.List(list)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list status/body = %d %s", listRecorder.Code, listRecorder.Body.String())
	}
	if listRecorder.Header().Get("Cache-Control") != "no-store" || listRecorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("list security headers = %#v", listRecorder.Header())
	}
	var payload struct {
		Items      []database.EgressAuditEvent   `json:"items"`
		Total      int                           `json:"total"`
		Page       int                           `json:"page"`
		PageSize   int                           `json:"pageSize"`
		TotalPages int                           `json:"totalPages"`
		Summary    database.EgressAuditSummary   `json:"summary"`
		Integrity  database.EgressAuditIntegrity `json:"integrity"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Total != 1 || payload.Page != 1 || payload.PageSize != 10 || payload.TotalPages != 1 || len(payload.Items) != 1 || payload.Items[0].ID != eventID || payload.Summary.Network != 1 || payload.Integrity.Status != "verified" || payload.Integrity.Events != 1 {
		t.Fatalf("list payload = %#v", payload)
	}
	if payload.Items[0].ChainSequence != 1 || len(payload.Items[0].PreviousHash) != 64 || len(payload.Items[0].EventHash) != 64 {
		t.Fatalf("list chain projection = %#v", payload.Items[0])
	}
	for _, forbidden := range []string{"authorization", "cookie", "requestBody", "responseBody", "secret-token"} {
		if strings.Contains(strings.ToLower(listRecorder.Body.String()), strings.ToLower(forbidden)) {
			t.Fatalf("list leaked forbidden field/value %q: %s", forbidden, listRecorder.Body.String())
		}
	}

	getRecorder := httptest.NewRecorder()
	get := egressAuditTestContext(getRecorder, http.MethodGet, "/api/egress-audit-events/"+eventID)
	get.Params = gin.Params{{Key: "id", Value: eventID}}
	handler.Get(get)
	if getRecorder.Code != http.StatusOK || !strings.Contains(getRecorder.Body.String(), eventID) {
		t.Fatalf("get status/body = %d %s", getRecorder.Code, getRecorder.Body.String())
	}
	for _, expected := range []string{"httpPacket", "token=plain", "Authorization", "Bearer plain-token", "responseBody", "complete response"} {
		if !strings.Contains(getRecorder.Body.String(), expected) {
			t.Fatalf("get omitted full packet value %q: %s", expected, getRecorder.Body.String())
		}
	}
	if getRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("get cache policy = %#v", getRecorder.Header())
	}

	jsonRecorder := httptest.NewRecorder()
	jsonContext := egressAuditTestContext(jsonRecorder, http.MethodGet, "/api/egress-audit-events/export?format=json")
	handler.Export(jsonContext)
	if jsonRecorder.Code != http.StatusOK || !strings.Contains(jsonRecorder.Header().Get("Content-Disposition"), ".json") || !strings.Contains(jsonRecorder.Body.String(), eventID) || jsonRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("json export = %d %#v %s", jsonRecorder.Code, jsonRecorder.Header(), jsonRecorder.Body.String())
	}

	csvRecorder := httptest.NewRecorder()
	csvContext := egressAuditTestContext(csvRecorder, http.MethodGet, "/api/egress-audit-events/export?format=csv")
	handler.Export(csvContext)
	if csvRecorder.Code != http.StatusOK || !strings.Contains(csvRecorder.Header().Get("Content-Type"), "text/csv") || !strings.Contains(csvRecorder.Body.String(), "'=formula title") || !strings.Contains(csvRecorder.Body.String(), "'=formula-rule") || !strings.Contains(csvRecorder.Body.String(), eventID) || csvRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("csv export = %d %#v %s", csvRecorder.Code, csvRecorder.Header(), csvRecorder.Body.String())
	}
	records, err := csv.NewReader(strings.NewReader(csvRecorder.Body.String())).ReadAll()
	if err != nil || len(records) != 2 || len(records[0]) != 34 || records[0][1] != "chain_sequence" || records[0][2] != "previous_hash" || records[0][3] != "event_hash" {
		t.Fatalf("csv chain columns = %#v, %v", records, err)
	}

	integrityRecorder := httptest.NewRecorder()
	integrityContext := egressAuditTestContext(integrityRecorder, http.MethodGet, "/api/egress-audit-events/integrity")
	handler.Integrity(integrityContext)
	if integrityRecorder.Code != http.StatusOK || !strings.Contains(integrityRecorder.Body.String(), `"status":"verified"`) || integrityRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("integrity = %d %#v %s", integrityRecorder.Code, integrityRecorder.Header(), integrityRecorder.Body.String())
	}
}

func TestEgressAuditHandlerDeletesSelectedEventsAndRejectsUnfilteredPurge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, eventID := newEgressAuditHandlerFixture(t)
	handler := NewEgressAuditHandler(db)

	unfilteredRecorder := httptest.NewRecorder()
	unfiltered := egressAuditTestContext(unfilteredRecorder, http.MethodDelete, "/api/egress-audit-events")
	unfiltered.Request = httptest.NewRequest(http.MethodDelete, "/api/egress-audit-events", strings.NewReader(`{}`))
	unfiltered.Request.Header.Set("Content-Type", "application/json")
	unfiltered.Set(security.ContextSessionKey, security.Session{UserID: "admin", Username: "admin", Scope: database.RBACScopeAll})
	handler.Delete(unfiltered)
	if unfilteredRecorder.Code != http.StatusBadRequest {
		t.Fatalf("unfiltered purge = %d %s", unfilteredRecorder.Code, unfilteredRecorder.Body.String())
	}

	deleteRecorder := httptest.NewRecorder()
	requestBody := `{"ids":["` + eventID + `"]}`
	request := egressAuditTestContext(deleteRecorder, http.MethodDelete, "/api/egress-audit-events")
	request.Request = httptest.NewRequest(http.MethodDelete, "/api/egress-audit-events", strings.NewReader(requestBody))
	request.Request.Header.Set("Content-Type", "application/json")
	request.Set(security.ContextSessionKey, security.Session{UserID: "admin", Username: "admin", Scope: database.RBACScopeAll})
	handler.Delete(request)
	if deleteRecorder.Code != http.StatusOK || !strings.Contains(deleteRecorder.Body.String(), `"deleted":1`) {
		t.Fatalf("selected purge = %d %s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if total, err := db.CountEgressAuditEvents(context.Background(), database.EgressAuditFilter{Scope: database.RBACScopeAll}); err != nil || total != 0 {
		t.Fatalf("events after purge = %d, %v", total, err)
	}
}

func TestEgressAuditHandlerFailsClosedWhenChainIsTampered(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, eventID := newEgressAuditHandlerFixture(t)
	if _, err := db.Exec(`DROP TRIGGER trg_egress_audit_append_only_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE egress_audit_events SET message = 'tampered provider detail' WHERE id = ?`, eventID); err != nil {
		t.Fatal(err)
	}
	handler := NewEgressAuditHandler(db)
	for name, invoke := range map[string]func(*gin.Context){
		"list":      handler.List,
		"integrity": handler.Integrity,
		"export":    handler.Export,
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := egressAuditTestContext(recorder, http.MethodGet, "/api/egress-audit-events")
			invoke(request)
			if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "完整性校验失败") || strings.Contains(recorder.Body.String(), "tampered provider detail") {
				t.Fatalf("tampered %s = %d %s", name, recorder.Code, recorder.Body.String())
			}
		})
	}
	recorder := httptest.NewRecorder()
	request := egressAuditTestContext(recorder, http.MethodGet, "/api/egress-audit-events/"+eventID)
	request.Params = gin.Params{{Key: "id", Value: eventID}}
	handler.Get(request)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "完整性校验失败") {
		t.Fatalf("tampered detail = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestEgressAuditHandlerRejectsInvalidClosedFiltersAndPagination(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := newEgressAuditHandlerFixture(t)
	handler := NewEgressAuditHandler(db)
	tests := []string{
		"?category=credential",
		"?event_type=raw_socket",
		"?decision=maybe",
		"?page=0",
		"?page_size=25",
		"?since=tomorrow",
		"?since=2026-08-23T00%3A00%3A00Z&until=2026-08-22T00%3A00%3A00Z",
		"?q=" + strings.Repeat("x", 201),
	}
	for _, query := range tests {
		recorder := httptest.NewRecorder()
		request := egressAuditTestContext(recorder, http.MethodGet, "/api/egress-audit-events"+query)
		handler.List(request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("query %q status/body = %d %s", query, recorder.Code, recorder.Body.String())
		}
	}

	recorder := httptest.NewRecorder()
	request := egressAuditTestContext(recorder, http.MethodGet, "/api/egress-audit-events/export?format=xml")
	handler.Export(request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid export status/body = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestSafeAuditCSVCellDefendsFormulaPrefixesAndControls(t *testing.T) {
	for _, value := range []string{"=formula", "+formula", "-formula", "@formula", "  =formula", "\t=formula"} {
		got := safeAuditCSVCell(value)
		if !strings.HasPrefix(got, "'") {
			t.Fatalf("formula-capable cell %q was not escaped: %q", value, got)
		}
		if strings.ContainsAny(got, "\x00\r\n\t") {
			t.Fatalf("escaped cell retained control characters: %q", got)
		}
	}
	if got := safeAuditCSVCell("safe value"); got != "safe value" {
		t.Fatalf("safe cell changed = %q", got)
	}
}

func TestOpenAPIEgressAuditProjectionDocumentsFullPacketAndControlledDeletion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/api/openapi/spec", nil)
	NewOpenAPIHandler(nil, zap.NewNop(), nil, nil).GetOpenAPISpec(context)
	if recorder.Code != http.StatusOK {
		t.Fatalf("openapi status/body = %d %s", recorder.Code, recorder.Body.String())
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	components := spec["components"].(map[string]interface{})
	schemas := components["schemas"].(map[string]interface{})
	auditSchema := schemas["EgressAuditEvent"].(map[string]interface{})
	if auditSchema["additionalProperties"] != false {
		t.Fatalf("audit schema is not closed: %#v", auditSchema)
	}
	properties := auditSchema["properties"].(map[string]interface{})
	for _, required := range []string{"chainSequence", "previousHash", "eventHash", "conversationId", "containerId", "agentId", "snapshotSha256", "domain", "decision", "ruleId", "upstreamRouteId", "httpPacket"} {
		if _, ok := properties[required]; !ok {
			t.Fatalf("audit schema missing safe trace field %q", required)
		}
	}
	integritySchema := schemas["EgressAuditIntegrity"].(map[string]interface{})
	if integritySchema["additionalProperties"] != false {
		t.Fatalf("integrity schema is not closed: %#v", integritySchema)
	}
	paths := spec["paths"].(map[string]interface{})
	if _, ok := paths["/api/egress-audit-events/integrity"]; !ok {
		t.Fatal("egress audit integrity path is missing")
	}
	if _, ok := paths["/api/egress-audit-events"].(map[string]interface{})["delete"]; !ok {
		t.Fatal("egress audit controlled delete operation is missing")
	}
	encoded := strings.ToLower(recorder.Body.String())
	for _, statement := range []string{"httppacket", "requestheaders", "requestbody", "audit:delete", "additionalproperties"} {
		if !strings.Contains(encoded, statement) {
			t.Fatalf("openapi is missing safety statement %q", statement)
		}
	}
}

func newEgressAuditHandlerFixture(t *testing.T) (*database.DB, string) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "egress-audit-handler.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conversation, err := db.CreateConversation("=formula title", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &containerruntime.EgressBoundarySnapshotSpec{
		ID: "11111111-1111-4111-8111-111111111111", SHA256: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	target := database.EgressAuditRuntimeTarget{
		ConversationTitle: conversation.Title,
		Record: containerruntime.InitializationRecord{
			ConversationID: conversation.ID, ProviderID: "provider-handler", RuntimeGeneration: 2,
			Spec: containerruntime.RuntimeSpec{ConversationID: conversation.ID, EgressGateway: &containerruntime.EgressGatewaySpec{BoundarySnapshot: snapshot}},
		},
	}
	event := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC),
		RequestType: egress.ActivityRequestHTTP, Domain: "allowed.example", ResolvedIPs: []string{"93.184.216.34"}, ConnectedIP: "93.184.216.34",
		Port: 80, Decision: egress.ActivityDecisionAllowed, RuleID: "=formula-rule", Reason: "allow-visit",
		Method: "GET", Path: "/safe", HTTPStatus: 200, Outcome: "completed", LatencyMS: 8, BytesDown: 42,
		HTTPPacket: &egress.HTTPPacket{RequestLine: "GET /safe?token=plain HTTP/1.1", RequestHeaders: map[string][]string{"Authorization": {"Bearer plain-token"}}, ResponseLine: "HTTP/1.1 200 OK", ResponseHeaders: map[string][]string{"Content-Type": {"text/plain"}}, ResponseBody: "complete response", ResponseBodyEncoding: "utf8"},
		SnapshotID: snapshot.ID, SnapshotSHA256: snapshot.SHA256,
	}
	inserted, err := db.AppendEgressNetworkAuditEvent(context.Background(), target, event)
	if err != nil || !inserted {
		t.Fatalf("append handler fixture = %v, %v", inserted, err)
	}
	items, err := db.ListEgressAuditEvents(context.Background(), database.EgressAuditFilter{Scope: database.RBACScopeAll, Limit: 10})
	if err != nil || len(items) != 1 {
		t.Fatalf("handler fixture items = %#v, %v", items, err)
	}
	return db, items[0].ID
}

func egressAuditTestContext(recorder *httptest.ResponseRecorder, method, target string) *gin.Context {
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(method, target, nil)
	context.Set(security.ContextSessionKey, security.Session{UserID: "admin", Username: "admin", Scope: database.RBACScopeAll})
	return context
}
