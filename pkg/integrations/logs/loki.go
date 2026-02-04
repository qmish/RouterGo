package logs

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

func NewLokiHook(url string) func(map[string]any) {
	if url == "" {
		return nil
	}
	client := &http.Client{Timeout: 3 * time.Second}
	return func(entry map[string]any) {
		payload := map[string]any{
			"streams": []any{
				map[string]any{
					"stream": map[string]string{"app": "routergo"},
					"values": [][]string{
						{time.Now().Format(time.RFC3339Nano), toJSON(entry)},
					},
				},
			},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		_, _ = client.Do(req)
	}
}

func toJSON(entry map[string]any) string {
	b, err := json.Marshal(entry)
	if err != nil {
		return "{}"
	}
	return string(b)
}
