package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
