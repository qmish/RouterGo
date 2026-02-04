package proxy

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

func StartHTTP3Server(ctx context.Context, addr, certFile, keyFile string, handler http.Handler) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	server := &http3.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
		},
		Handler: handler,
	}
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
