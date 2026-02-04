package enrich

import (
	"context"
	"sync"
	"time"
)

type Result struct {
	IP        string        `json:"ip"`
	Geo       *GeoInfo      `json:"geo,omitempty"`
	ASN       *ASNInfo      `json:"asn,omitempty"`
	Threat    *ThreatInfo   `json:"threat,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

type GeoInfo struct {
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
}

type ASNInfo struct {
	ASN  string `json:"asn,omitempty"`
	Org  string `json:"org,omitempty"`
	City string `json:"city,omitempty"`
}

type ThreatInfo struct {
	Score int `json:"score,omitempty"`
}

type Provider interface {
	Lookup(ctx context.Context, ip string) (any, error)
}

type Service struct {
	geo    Provider
	asn    Provider
	threat Provider
	cache  map[string]Result
	mu     sync.Mutex
	ttl    time.Duration
}

func NewService(geo Provider, asn Provider, threat Provider, ttl time.Duration) *Service {
	if ttl == 0 {
		ttl = 2 * time.Minute
	}
	return &Service{
		geo:    geo,
		asn:    asn,
		threat: threat,
		cache:  map[string]Result{},
		ttl:    ttl,
	}
}

func (s *Service) Lookup(ctx context.Context, ip string) (Result, error) {
	now := time.Now()
	s.mu.Lock()
	if cached, ok := s.cache[ip]; ok && now.Sub(cached.Timestamp) < s.ttl {
		s.mu.Unlock()
		return cached, nil
	}
	s.mu.Unlock()

	result := Result{IP: ip, Timestamp: now}
	if s.geo != nil {
		if geo, err := s.geo.Lookup(ctx, ip); err == nil {
			if v, ok := geo.(GeoInfo); ok {
				result.Geo = &v
			}
		}
	}
	if s.asn != nil {
		if asn, err := s.asn.Lookup(ctx, ip); err == nil {
			if v, ok := asn.(ASNInfo); ok {
				result.ASN = &v
			}
		}
	}
	if s.threat != nil {
		if threat, err := s.threat.Lookup(ctx, ip); err == nil {
			if v, ok := threat.(ThreatInfo); ok {
				result.Threat = &v
			}
		}
	}

	s.mu.Lock()
	s.cache[ip] = result
	s.mu.Unlock()
	return result, nil
}
