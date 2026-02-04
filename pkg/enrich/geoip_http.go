package enrich

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type GeoIPHTTP struct {
	url   string
	token string
	http  *http.Client
}

func NewGeoIPHTTP(url string, token string, timeout time.Duration) *GeoIPHTTP {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &GeoIPHTTP{
		url:   url,
		token: token,
		http:  &http.Client{Timeout: timeout},
	}
}

func (g *GeoIPHTTP) Lookup(ctx context.Context, ip string) (any, error) {
	if g.url == "" {
		return GeoInfo{}, nil
	}
	url := strings.ReplaceAll(g.url, "{ip}", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return GeoInfo{}, err
	}
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return GeoInfo{}, err
	}
	defer resp.Body.Close()
	var payload struct {
		Country string  `json:"country"`
		City    string  `json:"city"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return GeoInfo{}, err
	}
	return GeoInfo{
		Country: payload.Country,
		City:    payload.City,
		Lat:     payload.Lat,
		Lon:     payload.Lon,
	}, nil
}
