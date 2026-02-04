package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
)

type Config struct {
	ListenAddr      string
	H3Addr          string
	Upstream        string
	CacheSize       int
	CacheTTLSeconds int
	EnableGzip      bool
	EnableBrotli    bool
	EnableH3        bool
	HSTS            bool
	CertFile        string
	KeyFile         string
}

type Stats struct {
	CacheHits  uint64 `json:"cache_hits"`
	CacheMiss  uint64 `json:"cache_miss"`
	CacheSize  int    `json:"cache_size"`
	Compresses uint64 `json:"compress_total"`
}

type Proxy struct {
	cfg    Config
	cache  *Cache
	client *http.Client
	stats  Stats
	onHit      func()
	onMiss     func()
	onCompress func()
}

func NewProxy(cfg Config) (*Proxy, error) {
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	cfg.Upstream = upstream.String()
	cache := NewCache(cfg.CacheSize, time.Duration(cfg.CacheTTLSeconds)*time.Second)
	return &Proxy{
		cfg:   cfg,
		cache: cache,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		stats: Stats{},
	}, nil
}

func (p *Proxy) SetCallbacks(onHit, onMiss, onCompress func()) {
	p.onHit = onHit
	p.onMiss = onMiss
	p.onCompress = func() {
		p.stats.Compresses++
		if onCompress != nil {
			onCompress()
		}
	}
}

func (p *Proxy) Stats() Stats {
	stats := p.stats
	stats.CacheSize = p.cache.Size()
	return stats
}

func (p *Proxy) ClearCache() {
	p.cache.Clear()
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		p.proxyPass(w, r)
		return
	}

	key := r.Method + ":" + r.URL.String()
	if cached, ok := p.cache.Get(key); ok {
		p.stats.CacheHits++
		if p.onHit != nil {
			p.onHit()
		}
		writeResponse(w, cached, r, p.cfg, p.onCompress)
		return
	}
	p.stats.CacheMiss++
	if p.onMiss != nil {
		p.onMiss()
	}

	resp, err := p.fetch(r)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	p.cache.Set(key, resp)
	writeResponse(w, resp, r, p.cfg, p.onCompress)
}

func (p *Proxy) fetch(r *http.Request) (*CacheValue, error) {
	upstreamURL, err := url.Parse(p.cfg.Upstream)
	if err != nil {
		return nil, err
	}
	upstreamURL.Path = r.URL.Path
	upstreamURL.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), nil)
	if err != nil {
		return nil, err
	}
	copyHeaders(req.Header, r.Header)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	return &CacheValue{
		Status:  resp.StatusCode,
		Headers: headers,
		Body:    body,
	}, nil
}

func (p *Proxy) proxyPass(w http.ResponseWriter, r *http.Request) {
	resp, err := p.fetch(r)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	writeResponse(w, resp, r, p.cfg, p.onCompress)
}

func writeResponse(w http.ResponseWriter, resp *CacheValue, r *http.Request, cfg Config, onCompress func()) {
	headers := make(http.Header)
	for k, v := range resp.Headers {
		headers.Set(k, v)
	}
	if cfg.HSTS {
		headers.Set("Strict-Transport-Security", "max-age=31536000")
	}
	body := resp.Body
	encoding := selectEncoding(r.Header.Get("Accept-Encoding"), cfg)
	if encoding == "gzip" {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		_, _ = gw.Write(body)
		_ = gw.Close()
		body = buf.Bytes()
		headers.Set("Content-Encoding", "gzip")
		if onCompress != nil {
			onCompress()
		}
	}
	if encoding == "br" {
		body = brotliCompress(body)
		headers.Set("Content-Encoding", "br")
		if onCompress != nil {
			onCompress()
		}
	}
	for k, v := range headers {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(resp.Status)
	_, _ = w.Write(body)
}

func selectEncoding(accept string, cfg Config) string {
	accept = strings.ToLower(accept)
	if cfg.EnableBrotli && strings.Contains(accept, "br") {
		return "br"
	}
	if cfg.EnableGzip && strings.Contains(accept, "gzip") {
		return "gzip"
	}
	return ""
}

func brotliCompress(data []byte) []byte {
	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	_, _ = bw.Write(data)
	_ = bw.Close()
	return buf.Bytes()
}

func copyHeaders(dst, src http.Header) {
	for k, v := range src {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, val := range v {
			dst.Add(k, val)
		}
	}
}

func StartHTTPServer(ctx context.Context, addr string, handler http.Handler) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
