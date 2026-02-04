package enrich

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type ThreatAbuseIPDB struct {
	apiKey string
	http   *http.Client
}

func NewThreatAbuseIPDB(apiKey string, timeout time.Duration) *ThreatAbuseIPDB {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &ThreatAbuseIPDB{
		apiKey: apiKey,
		http:   &http.Client{Timeout: timeout},
	}
}

func (t *ThreatAbuseIPDB) Lookup(ctx context.Context, ip string) (any, error) {
	if t.apiKey == "" {
		return ThreatInfo{}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.abuseipdb.com/api/v2/check?ipAddress="+ip, nil)
	if err != nil {
		return ThreatInfo{}, err
	}
	req.Header.Set("Key", t.apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := t.http.Do(req)
	if err != nil {
		return ThreatInfo{}, err
	}
	defer resp.Body.Close()
	var payload struct {
		Data struct {
			Score int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ThreatInfo{}, err
	}
	return ThreatInfo{Score: payload.Data.Score}, nil
}
