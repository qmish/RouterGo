package logs

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

func NewElasticHook(url string) func(map[string]any) {
	if url == "" {
		return nil
	}
	client := &http.Client{Timeout: 3 * time.Second}
	return func(entry map[string]any) {
		body, _ := json.Marshal(entry)
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		_, _ = client.Do(req)
	}
}
