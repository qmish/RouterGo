package enrich

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type ASNIPInfo struct {
	token string
	http  *http.Client
}

func NewASNIPInfo(token string, timeout time.Duration) *ASNIPInfo {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &ASNIPInfo{
		token: token,
		http:  &http.Client{Timeout: timeout},
	}
}

func (a *ASNIPInfo) Lookup(ctx context.Context, ip string) (any, error) {
	if a.token == "" {
		return ASNInfo{}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipinfo.io/"+ip+"/json?token="+a.token, nil)
	if err != nil {
		return ASNInfo{}, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return ASNInfo{}, err
	}
	defer resp.Body.Close()
	var payload struct {
		Org  string `json:"org"`
		City string `json:"city"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ASNInfo{}, err
	}
	return ASNInfo{
		ASN:  payload.Org,
		Org:  payload.Org,
		City: payload.City,
	}, nil
}
