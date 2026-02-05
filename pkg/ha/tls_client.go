package ha

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

type TLSConfig struct {
	Enabled       bool
	CertFile      string
	KeyFile       string
	ClientCAFile  string
}

func NewHTTPClient(cfg TLSConfig, timeout time.Duration) (*http.Client, error) {
	if !cfg.Enabled {
		return &http.Client{Timeout: timeout}, nil
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("tls enabled but cert or key missing")
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.ClientCAFile != "" {
		caData, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("invalid client ca pem")
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}
