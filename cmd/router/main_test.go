package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"router-go/internal/config"
	"router-go/internal/logger"
	"router-go/internal/metrics"
	"router-go/pkg/firewall"
	"router-go/pkg/nat"
	"router-go/pkg/network"
	"router-go/pkg/qos"

	"github.com/prometheus/client_golang/prometheus"
)

func TestBuildRoutesSkipsInvalid(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteConfig{
			{
				Destination: "10.0.0.0/24",
				Gateway:     "10.0.0.1",
				Interface:   "eth0",
				Metric:      10,
			},
			{
				Destination: "bad",
				Gateway:     "10.0.0.2",
			},
		},
	}
	log := logger.New("info")
	table := buildRoutes(cfg, log)

	routes := table.Routes()
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Destination.String() != "10.0.0.0/24" {
		t.Fatalf("unexpected destination: %s", routes[0].Destination.String())
	}
	if routes[0].Gateway.String() != "10.0.0.1" {
		t.Fatalf("unexpected gateway: %s", routes[0].Gateway.String())
	}
}

func TestBuildFirewallSkipsInvalidAndDefaults(t *testing.T) {
	cfg := &config.Config{
		FirewallDefaults: config.FirewallDefaultsConfig{
			Input:   "accept",
			Output:  "drop",
			Forward: "reject",
		},
		Firewall: []config.FirewallRuleConfig{
			{
				Chain:  "INPUT",
				Action: "ACCEPT",
				SrcIP:  "bad",
			},
			{
				Chain:    "INPUT",
				Action:   "ACCEPT",
				Protocol: "TCP",
				DstIP:    "192.168.1.0/24",
				DstPort:  80,
			},
		},
	}
	log := logger.New("info")
	engine := buildFirewall(cfg, log)

	rules := engine.Rules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Action != firewall.ActionAccept {
		t.Fatalf("unexpected action: %s", rules[0].Action)
	}
	defaults := engine.DefaultPolicies()
	if defaults["INPUT"] != firewall.ActionAccept {
		t.Fatalf("unexpected input default: %s", defaults["INPUT"])
	}
	if defaults["OUTPUT"] != firewall.ActionDrop {
		t.Fatalf("unexpected output default: %s", defaults["OUTPUT"])
	}
	if defaults["FORWARD"] != firewall.ActionReject {
		t.Fatalf("unexpected forward default: %s", defaults["FORWARD"])
	}
}

func TestBuildNATSkipsInvalid(t *testing.T) {
	cfg := &config.Config{
		NAT: []config.NATRuleConfig{
			{
				Type:   "SNAT",
				SrcIP:  "bad",
				ToIP:   "203.0.113.1",
				ToPort: 1234,
			},
			{
				Type:   "DNAT",
				DstIP:  "10.1.0.0/16",
				ToIP:   "192.168.1.10",
				ToPort: 8080,
			},
		},
	}
	log := logger.New("info")
	table := buildNAT(cfg, log)

	rules := table.Rules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Type != nat.TypeDNAT {
		t.Fatalf("unexpected rule type: %s", rules[0].Type)
	}
}

func TestBuildQoSQueueAddsDefault(t *testing.T) {
	cfg := &config.Config{
		QoS: []config.QoSClassConfig{
			{Name: "voice", Priority: 10, RateLimitKbps: 64},
		},
	}
	queue := buildQoSQueue(cfg)
	classes := queue.Classes()
	if !containsClass(classes, "voice") {
		t.Fatalf("expected voice class to exist")
	}
	if !containsClass(classes, "default") {
		t.Fatalf("expected default class to exist")
	}
}

func TestParseFirewallAction(t *testing.T) {
	if got := parseFirewallAction(" accept ", firewall.ActionDrop); got != firewall.ActionAccept {
		t.Fatalf("expected accept, got %s", got)
	}
	if got := parseFirewallAction("DROP", firewall.ActionAccept); got != firewall.ActionDrop {
		t.Fatalf("expected drop, got %s", got)
	}
	if got := parseFirewallAction("unknown", firewall.ActionReject); got != firewall.ActionReject {
		t.Fatalf("expected fallback, got %s", got)
	}
}

func TestBuildIDSDisabled(t *testing.T) {
	cfg := &config.Config{IDS: config.IDSConfig{Enabled: false}}
	if buildIDS(cfg) != nil {
		t.Fatalf("expected nil engine when disabled")
	}
}

func TestBuildIDSEnabled(t *testing.T) {
	cfg := &config.Config{IDS: config.IDSConfig{
		Enabled:        true,
		BehaviorAction: "DROP",
		WhitelistSrc:   []string{"10.0.0.0/24"},
	}}
	engine := buildIDS(cfg)
	if engine == nil {
		t.Fatalf("expected engine when enabled")
	}
}

func TestParseCIDRsSkipsInvalid(t *testing.T) {
	nets := parseCIDRs([]string{"10.0.0.0/24", "bad"})
	if len(nets) != 1 {
		t.Fatalf("expected 1 network, got %d", len(nets))
	}
	if nets[0].String() != "10.0.0.0/24" {
		t.Fatalf("unexpected network: %s", nets[0].String())
	}
}

func TestBuildLocalIPs(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.InterfaceConfig{
			{Name: "eth0", IP: "10.0.0.1/24"},
			{Name: "eth1", IP: "bad"},
		},
	}
	ips := buildLocalIPs(cfg)
	if len(ips) != 1 {
		t.Fatalf("expected 1 local ip, got %d", len(ips))
	}
	if !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("unexpected ip: %s", ips[0].String())
	}
}

func TestDetermineChainMain(t *testing.T) {
	local := []net.IP{net.ParseIP("10.0.0.1")}
	if got := determineChain(network.Packet{Metadata: network.PacketMetadata{DstIP: net.ParseIP("10.0.0.1")}}, local); got != "INPUT" {
		t.Fatalf("expected INPUT, got %s", got)
	}
	if got := determineChain(network.Packet{Metadata: network.PacketMetadata{SrcIP: net.ParseIP("10.0.0.1")}}, local); got != "OUTPUT" {
		t.Fatalf("expected OUTPUT, got %s", got)
	}
	if got := determineChain(network.Packet{Metadata: network.PacketMetadata{SrcIP: net.ParseIP("10.0.0.2")}}, local); got != "FORWARD" {
		t.Fatalf("expected FORWARD, got %s", got)
	}
}

func TestLoadP2PKeys(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "pub.key")
	privPath := filepath.Join(dir, "priv.key")
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	if err := os.WriteFile(privPath, []byte(hex.EncodeToString(priv)), 0644); err != nil {
		t.Fatalf("write priv: %v", err)
	}

	gotPub, gotPriv := loadP2PKeys(pubPath, privPath, logger.New("info"))
	if !bytes.Equal(gotPub, pub) {
		t.Fatalf("public key mismatch")
	}
	if !bytes.Equal(gotPriv, priv) {
		t.Fatalf("private key mismatch")
	}
}

func TestLoadTLSConfig(t *testing.T) {
	certFile, keyFile, caFile := writeTestCerts(t)
	cfg := config.TLSConfig{
		CertFile:          certFile,
		KeyFile:           keyFile,
		ClientCAFile:      caFile,
		RequireClientCert: true,
	}

	tlsConfig, err := loadTLSConfig(cfg, logger.New("info"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected mTLS client auth")
	}
	if tlsConfig.ClientCAs == nil {
		t.Fatalf("expected client CAs to be set")
	}
}

func TestLoadPresets(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"id":"demo","name":"Demo","settings":{}}`)
	if err := os.WriteFile(filepath.Join(dir, "demo.json"), data, 0644); err != nil {
		t.Fatalf("write preset: %v", err)
	}
	cfg := &config.Config{Presets: config.PresetsConfig{Dir: dir}}
	store := loadPresets(cfg, logger.New("info"))
	if store == nil {
		t.Fatalf("expected store")
	}
	list := store.List()
	if len(list) != 1 || list[0].ID != "demo" {
		t.Fatalf("unexpected presets list: %+v", list)
	}
}

func TestBuildObservability(t *testing.T) {
	cfg := &config.Config{Observability: config.ObservabilityConfig{Enabled: true, TracesLimit: 5}}
	store := buildObservability(cfg, logger.New("info"))
	if store == nil {
		t.Fatalf("expected store")
	}
	if store.Limit() != 5 {
		t.Fatalf("unexpected limit: %d", store.Limit())
	}
}

func TestStartAlertingEnabled(t *testing.T) {
	cfg := &config.Config{Observability: config.ObservabilityConfig{
		Enabled:              true,
		AlertsEnabled:        true,
		AlertsLimit:          10,
		AlertIntervalSeconds: 1,
		DropsThreshold:       1,
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := prometheus.NewRegistry()
	metricsSrv := metrics.NewWithRegistry(reg)
	store := startAlerting(ctx, cfg, metricsSrv, logger.New("info"))
	if store == nil {
		t.Fatalf("expected alert store")
	}
	if store.Limit() != 10 {
		t.Fatalf("unexpected limit: %d", store.Limit())
	}
}

func TestDequeueAndWriteBatchMain(t *testing.T) {
	queue := qos.NewQueueManager([]qos.Class{{Name: "voice", Priority: 10}})
	pkt := network.Packet{Data: []byte{1, 2}, Metadata: network.PacketMetadata{Protocol: "TCP"}}
	if ok, _, _ := queue.Enqueue(pkt); !ok {
		t.Fatalf("expected enqueue to succeed")
	}

	io := &mockPacketIO{}
	metricsSrv := metrics.NewWithRegistry(prometheus.NewRegistry())
	if ok := dequeueAndWriteBatch(queue, io, metricsSrv, 5); !ok {
		t.Fatalf("expected dequeue to succeed")
	}
	if len(io.writes) != 1 {
		t.Fatalf("expected 1 write, got %d", len(io.writes))
	}
	if metricsSrv.Snapshot().TxPackets != 1 {
		t.Fatalf("expected tx packets to be 1")
	}
}

type mockPacketIO struct {
	writes []network.Packet
}

func (m *mockPacketIO) ReadPacket(ctx context.Context) (network.Packet, error) {
	return network.Packet{}, errors.New("not implemented")
}

func (m *mockPacketIO) WritePacket(ctx context.Context, pkt network.Packet) error {
	m.writes = append(m.writes, pkt)
	return nil
}

func (m *mockPacketIO) Close() error {
	return nil
}

func containsClass(classes []qos.Class, name string) bool {
	for _, cl := range classes {
		if cl.Name == name {
			return true
		}
	}
	return false
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
