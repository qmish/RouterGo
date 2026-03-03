package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"router-go/internal/config"
	"router-go/internal/metrics"
	"router-go/pkg/nat"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func setupConfigRouter(health func(*config.Config) error) *gin.Engine {
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(&config.Config{}, health)
	h := &Handlers{
		Routes:    routing.NewTable(nil),
		NAT:       nat.NewTable(nil),
		QoS:       qos.NewQueueManager(nil),
		ConfigMgr: manager,
		Metrics:   metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := gin.New()
	RegisterRoutes(router, h)
	return router
}

func TestApplyConfigSuccess(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	payload := map[string]any{
		"config_yaml": "api:\n  address: :8080\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestApplyConfigInvalid(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	payload := map[string]any{
		"config_yaml": "interfaces:\n  - ip: 10.0.0.1/24\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPlanConfigSuccess(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	payload := map[string]any{
		"config_yaml": "api:\n  address: :8081\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/plan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestPlanConfigInvalid(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	payload := map[string]any{
		"config_yaml": "interfaces:\n  - ip: 10.0.0.1/24\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/plan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestApplyConfigHealthFail(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return errors.New("fail") })
	payload := map[string]any{
		"config_yaml": "selfheal:\n  enabled: true\napi:\n  address: :8080\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPlanConfigHealthFail(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return errors.New("fail") })
	payload := map[string]any{
		"config_yaml": "selfheal:\n  enabled: true\napi:\n  address: :8080\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/plan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestRollbackConfig(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	payload := map[string]any{
		"config_yaml": "api:\n  address: :8080\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	req = httptest.NewRequest(http.MethodPost, "/api/config/rollback", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/config/snapshots", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRollbackConfigWithoutSnapshots(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	req := httptest.NewRequest(http.MethodPost, "/api/config/rollback", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestGetConfigHistory(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	payload := map[string]any{
		"config_yaml": "api:\n  address: :8080\n",
		"actor":       "qa-user",
		"reason":      "api bind update",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for apply, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/config/history", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if _, ok := out["history"]; !ok {
		t.Fatalf("expected history field")
	}
	rawHistory, ok := out["history"].([]any)
	if !ok || len(rawHistory) == 0 {
		t.Fatalf("expected non-empty history array")
	}
	entry, ok := rawHistory[0].(map[string]any)
	if !ok {
		t.Fatalf("expected history entry object")
	}
	if entry["actor"] != "qa-user" {
		t.Fatalf("expected actor qa-user, got %v", entry["actor"])
	}
}

func TestGetConfigDiff(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	payload := map[string]any{
		"config_yaml": "api:\n  address: :8081\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for apply, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/config/diff?from=0&to=1", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for diff, got %d", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if _, ok := out["changed_sections"]; !ok {
		t.Fatalf("expected changed_sections field")
	}
}

func TestGetConfigDiffInvalidParams(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	req := httptest.NewRequest(http.MethodGet, "/api/config/diff?from=a&to=1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestGetConfigHistoryExport(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	payload := map[string]any{
		"config_yaml": "api:\n  address: :8083\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for apply, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/config/history/export", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct == "" {
		t.Fatalf("expected content type header")
	}
	if cd := w.Header().Get("Content-Disposition"); cd == "" {
		t.Fatalf("expected content disposition header")
	}
}

func TestGetConfigBackup(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	payload := map[string]any{
		"config_yaml": "api:\n  address: :8084\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for apply, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/config/backup", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(w.Body.Bytes()) == 0 {
		t.Fatalf("expected non-empty backup body")
	}
}

func TestRestoreConfigSuccess(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })

	applyPayload := map[string]any{
		"config_yaml": "api:\n  address: :8085\n",
	}
	applyBody, _ := json.Marshal(applyPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(applyBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for apply, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/config/backup", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for backup, got %d", w.Code)
	}
	backup := w.Body.String()

	applyPayload = map[string]any{
		"config_yaml": "api:\n  address: :9090\n",
	}
	applyBody, _ = json.Marshal(applyPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(applyBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for apply-2, got %d", w.Code)
	}

	restorePayload := map[string]any{
		"backup_json": backup,
		"actor":       "qa-restore",
		"reason":      "restore backup",
	}
	restoreBody, _ := json.Marshal(restorePayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/restore", bytes.NewReader(restoreBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for restore, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/config/export?format=json", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for export, got %d", w.Code)
	}
	var cfgOut map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &cfgOut); err != nil {
		t.Fatalf("invalid config json: %v", err)
	}
	apiSection, ok := cfgOut["API"].(map[string]any)
	if !ok {
		t.Fatalf("expected api section in config export")
	}
	if apiSection["Address"] != ":8085" {
		t.Fatalf("expected restored address :8085, got %v", apiSection["Address"])
	}
}

func TestRestoreConfigInvalidBackup(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	restorePayload := map[string]any{
		"backup_json": "{bad-json",
	}
	restoreBody, _ := json.Marshal(restorePayload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/restore", bytes.NewReader(restoreBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid backup, got %d", w.Code)
	}
}

func TestGetAuthInfo(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAPIKeysCreateRotateRevoke(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })

	createPayload := map[string]any{
		"role":   "admin",
		"scopes": []string{"security:read", "security:write"},
	}
	body, _ := json.Marshal(createPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/security/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on create, got %d", w.Code)
	}
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("invalid create response: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("expected key id in create response")
	}
	if _, ok := created["api_key"]; !ok {
		t.Fatalf("expected api_key in create response")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/security/keys", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on list, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/security/keys/"+id+"/rotate", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on rotate, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/security/keys/"+id+"/revoke", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on revoke, got %d", w.Code)
	}
}

func TestPolicyBundleExportImport(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })

	exportReq := httptest.NewRequest(http.MethodGet, "/api/policy/bundle/export", nil)
	exportRes := httptest.NewRecorder()
	router.ServeHTTP(exportRes, exportReq)
	if exportRes.Code != http.StatusOK {
		t.Fatalf("expected 200 on export, got %d", exportRes.Code)
	}

	importPayload := map[string]any{
		"mode": "replace",
		"bundle": map[string]any{
			"routes": []map[string]any{
				{
					"destination": "10.10.0.0/16",
					"gateway":     "10.0.0.1",
					"interface":   "eth0",
					"metric":      10,
				},
			},
		},
	}
	body, _ := json.Marshal(importPayload)
	importReq := httptest.NewRequest(http.MethodPost, "/api/policy/bundle/import", bytes.NewReader(body))
	importReq.Header.Set("Content-Type", "application/json")
	importRes := httptest.NewRecorder()
	router.ServeHTTP(importRes, importReq)
	if importRes.Code != http.StatusOK {
		t.Fatalf("expected 200 on import, got %d: %s", importRes.Code, importRes.Body.String())
	}

	cfgReq := httptest.NewRequest(http.MethodGet, "/api/config/export?format=json", nil)
	cfgRes := httptest.NewRecorder()
	router.ServeHTTP(cfgRes, cfgReq)
	if cfgRes.Code != http.StatusOK {
		t.Fatalf("expected 200 on config export, got %d", cfgRes.Code)
	}
	var cfgOut map[string]any
	if err := json.Unmarshal(cfgRes.Body.Bytes(), &cfgOut); err != nil {
		t.Fatalf("invalid config export json: %v", err)
	}
	routes, ok := cfgOut["Routes"].([]any)
	if !ok || len(routes) != 1 {
		t.Fatalf("expected one route after import, got %v", cfgOut["Routes"])
	}
}

func TestWebhookLifecycleAndTestEvent(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	received := make(chan map[string]any, 1)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
			received <- payload
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	createPayload := map[string]any{
		"id":      "ops-webhook",
		"url":     sink.URL,
		"events":  []string{"webhook.test"},
		"enabled": true,
	}
	body, _ := json.Marshal(createPayload)
	createReq := httptest.NewRequest(http.MethodPost, "/api/integrations/webhooks", bytes.NewReader(body))
	createReq.Header.Set("Content-Type", "application/json")
	createRes := httptest.NewRecorder()
	router.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusOK {
		t.Fatalf("expected 200 on create webhook, got %d", createRes.Code)
	}

	testReq := httptest.NewRequest(http.MethodPost, "/api/integrations/webhooks/ops-webhook/test", bytes.NewReader([]byte("{}")))
	testReq.Header.Set("Content-Type", "application/json")
	testRes := httptest.NewRecorder()
	router.ServeHTTP(testRes, testReq)
	if testRes.Code != http.StatusOK {
		t.Fatalf("expected 200 on test webhook, got %d", testRes.Code)
	}

	select {
	case payload := <-received:
		if payload["event"] != "webhook.test" {
			t.Fatalf("expected webhook.test event, got %v", payload["event"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("expected webhook delivery")
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/integrations/webhooks/ops-webhook", nil)
	deleteRes := httptest.NewRecorder()
	router.ServeHTTP(deleteRes, deleteReq)
	if deleteRes.Code != http.StatusOK {
		t.Fatalf("expected 200 on delete webhook, got %d", deleteRes.Code)
	}
}

func TestWebhookMetricsTracksFailuresAndSuccess(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })

	sinkOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer sinkOK.Close()
	sinkFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer sinkFail.Close()

	createOK := map[string]any{
		"id":          "wh-ok",
		"url":         sinkOK.URL,
		"events":      []string{"webhook.test"},
		"enabled":     true,
		"max_retries": 0,
	}
	body, _ := json.Marshal(createOK)
	req := httptest.NewRequest(http.MethodPost, "/api/integrations/webhooks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on create ok webhook, got %d", w.Code)
	}

	createFail := map[string]any{
		"id":          "wh-fail",
		"url":         sinkFail.URL,
		"events":      []string{"webhook.test"},
		"enabled":     true,
		"max_retries": 1,
		"timeout_ms":  500,
	}
	body, _ = json.Marshal(createFail)
	req = httptest.NewRequest(http.MethodPost, "/api/integrations/webhooks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on create fail webhook, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/integrations/webhooks/wh-ok/test", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on test ok webhook, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/integrations/webhooks/wh-fail/test", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on test failed webhook, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/integrations/webhooks/metrics", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on metrics, got %d", w.Code)
	}
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid metrics json: %v", err)
	}
	if len(out) < 2 {
		t.Fatalf("expected at least two metrics entries, got %d", len(out))
	}
	seenOK := false
	seenFail := false
	for _, metric := range out {
		id, _ := metric["webhook_id"].(string)
		switch id {
		case "wh-ok":
			seenOK = true
			success, _ := metric["success_total"].(float64)
			if success < 1 {
				t.Fatalf("expected success_total >= 1 for wh-ok, got %v", metric["success_total"])
			}
		case "wh-fail":
			seenFail = true
			failed, _ := metric["failed_total"].(float64)
			attempts, _ := metric["attempts_total"].(float64)
			if failed < 1 {
				t.Fatalf("expected failed_total >= 1 for wh-fail, got %v", metric["failed_total"])
			}
			if attempts < 2 {
				t.Fatalf("expected attempts_total >= 2 for wh-fail, got %v", metric["attempts_total"])
			}
		}
	}
	if !seenOK || !seenFail {
		t.Fatalf("expected metrics for both webhook ids")
	}
}

func TestWebhookFailureQueueAndRetry(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	var attempts atomic.Int32
	flappySink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer flappySink.Close()

	createPayload := map[string]any{
		"id":          "wh-flappy",
		"url":         flappySink.URL,
		"events":      []string{"webhook.test"},
		"enabled":     true,
		"max_retries": 0,
	}
	body, _ := json.Marshal(createPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/integrations/webhooks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on webhook create, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/integrations/webhooks/wh-flappy/test", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on first flappy call, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/integrations/webhooks/failures", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on failures list, got %d", w.Code)
	}
	var failures []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &failures); err != nil {
		t.Fatalf("invalid failures json: %v", err)
	}
	if len(failures) == 0 {
		t.Fatalf("expected at least one failed delivery entry")
	}
	failureID, _ := failures[0]["id"].(string)
	if failureID == "" {
		t.Fatalf("expected failure id")
	}

	req = httptest.NewRequest(http.MethodPost, "/api/integrations/webhooks/failures/"+failureID+"/retry", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on retry, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/integrations/webhooks/failures", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on failures list after retry, got %d", w.Code)
	}
	failures = nil
	if err := json.Unmarshal(w.Body.Bytes(), &failures); err != nil {
		t.Fatalf("invalid failures json: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("expected empty failures after successful retry, got %d", len(failures))
	}
}

func TestWebhookSignatureHeaders(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	secret := "test-secret-123"
	received := make(chan map[string]string, 1)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)
		received <- map[string]string{
			"event":     r.Header.Get("X-RouterGo-Event"),
			"timestamp": r.Header.Get("X-RouterGo-Timestamp"),
			"signature": r.Header.Get("X-RouterGo-Signature"),
			"body":      string(body),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	createPayload := map[string]any{
		"id":      "wh-signed",
		"url":     sink.URL,
		"events":  []string{"webhook.test"},
		"enabled": true,
		"secret":  secret,
	}
	body, _ := json.Marshal(createPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/integrations/webhooks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on create signed webhook, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/integrations/webhooks/wh-signed/test", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on signed webhook test, got %d", w.Code)
	}

	var captured map[string]string
	select {
	case captured = <-received:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected signed webhook delivery")
	}
	if captured["event"] != "webhook.test" {
		t.Fatalf("expected webhook.test event header, got %q", captured["event"])
	}
	if captured["timestamp"] == "" {
		t.Fatalf("expected non-empty timestamp header")
	}
	if captured["signature"] == "" {
		t.Fatalf("expected non-empty signature header")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(captured["body"]))
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if captured["signature"] != expected {
		t.Fatalf("expected signature %q, got %q", expected, captured["signature"])
	}
}

func TestMonitoringSLOEndpoint(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	req := httptest.NewRequest(http.MethodGet, "/api/monitoring/slo", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if _, ok := out["apply_success_rate"]; !ok {
		t.Fatalf("missing apply_success_rate field")
	}
}
