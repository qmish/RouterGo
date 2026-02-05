package ha

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewHTTPClientTLSConfig(t *testing.T) {
	certFile, keyFile, caFile := writeTestCerts(t)

	client, err := NewHTTPClient(TLSConfig{
		Enabled:       true,
		CertFile:      certFile,
		KeyFile:       keyFile,
		ClientCAFile:  caFile,
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.Timeout != 5*time.Second {
		t.Fatalf("expected timeout 5s, got %s", client.Timeout)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatalf("expected tls transport to be configured")
	}
	if tr.TLSClientConfig.RootCAs == nil {
		t.Fatalf("expected RootCAs to be set")
	}
	if len(tr.TLSClientConfig.Certificates) == 0 {
		t.Fatalf("expected client certificate to be set")
	}
}

func TestNewHTTPClientTLSConfigMissingKey(t *testing.T) {
	_, err := NewHTTPClient(TLSConfig{Enabled: true, CertFile: "x"}, time.Second)
	if err == nil {
		t.Fatalf("expected error for missing key")
	}
}

func TestNewHTTPClientTLSDisabled(t *testing.T) {
	client, err := NewHTTPClient(TLSConfig{Enabled: false}, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.Timeout != 2*time.Second {
		t.Fatalf("expected timeout 2s, got %s", client.Timeout)
	}
}

func writeTestCerts(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "RouterGo Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "RouterGo Test Client",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	caFile := filepath.Join(dir, "ca.pem")
	certFile := filepath.Join(dir, "client.pem")
	keyFile := filepath.Join(dir, "client.key")

	writePEM(t, caFile, "CERTIFICATE", caDER)
	writePEM(t, certFile, "CERTIFICATE", clientDER)
	writePEM(t, keyFile, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))

	return certFile, keyFile, caFile
}

func writePEM(t *testing.T, path string, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pem file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("encode pem: %v", err)
	}
}
