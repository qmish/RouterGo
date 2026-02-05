package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"router-go/pkg/routing"
)

func TestEngineReset(t *testing.T) {
	table := routing.NewTable(nil)
	engine := NewEngine(Config{PeerID: "node-1"}, table, nil, nil, nil)

	engine.peers["node-2"] = Peer{ID: "node-2", Addr: "127.0.0.1:10000", LastSeen: time.Now()}
	engine.routes = []routing.Route{{Interface: "eth0"}}
	engine.routeSet["r1"] = struct{}{}
	engine.replayGuard["node-2"] = map[uint64]struct{}{1: {}}

	engine.Reset()
	if len(engine.peers) != 0 {
		t.Fatalf("expected peers cleared")
	}
	if len(engine.routes) != 0 {
		t.Fatalf("expected routes cleared")
	}
	if len(engine.routeSet) != 0 {
		t.Fatalf("expected route set cleared")
	}
	if len(engine.replayGuard) != 0 {
		t.Fatalf("expected replay guard cleared")
	}
}

func TestHandleHelloAddsPeer(t *testing.T) {
	table := routing.NewTable(nil)
	peerCount := 0
	peerPub, peerPriv, _ := ed25519.GenerateKey(nil)
	_, localPriv, _ := ed25519.GenerateKey(nil)
	engine := NewEngine(Config{PeerID: "self", PrivateKey: localPriv, PublicKey: peerPub}, table, nil, func() { peerCount++ }, nil)

	msg := message{Type: "HELLO", PeerID: "peer-1"}
	msg.Seq = 1
	msg.Timestamp = time.Now().Unix()
	msg.TTL = 2
	msg.Signature, _ = signMessage(msg, peerPriv)
	data, _ := json.Marshal(msg)
	if err := engine.handleMessage(data, "1.2.3.4"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	peers := engine.Peers()
	if len(peers) != 1 || peers[0].ID != "peer-1" {
		t.Fatalf("expected peer added")
	}
	if peerCount != 1 {
		t.Fatalf("expected peer callback")
	}
}

func TestHandleRoutesSync(t *testing.T) {
	table := routing.NewTable(nil)
	routeSync := 0
	peerPub, peerPriv, _ := ed25519.GenerateKey(nil)
	_, localPriv, _ := ed25519.GenerateKey(nil)
	engine := NewEngine(Config{PeerID: "self", PrivateKey: localPriv, PublicKey: peerPub}, table, nil, nil, func() { routeSync++ })

	msg := message{
		Type:   "ROUTES",
		PeerID: "peer-1",
		Routes: []RouteAdvert{
			{Destination: "10.0.0.0/8", Gateway: "192.168.1.1", Interface: "eth0", Metric: 100},
		},
	}
	msg.Seq = 1
	msg.Timestamp = time.Now().Unix()
	msg.TTL = 2
	msg.Signature, _ = signMessage(msg, peerPriv)
	data, _ := json.Marshal(msg)
	if err := engine.handleMessage(data, "1.2.3.4"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(engine.Routes()) == 0 {
		t.Fatalf("expected routes synced")
	}
	if routeSync == 0 {
		t.Fatalf("expected sync callback")
	}
}

func TestPeerPrune(t *testing.T) {
	table := routing.NewTable(nil)
	peerPub, peerPriv, _ := ed25519.GenerateKey(nil)
	_, localPriv, _ := ed25519.GenerateKey(nil)
	engine := NewEngine(Config{PeerID: "self", PeerTTL: 1 * time.Second, PrivateKey: localPriv, PublicKey: peerPub}, table, nil, nil, nil)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	engine.nowFunc = func() time.Time { return base }

	msg := message{Type: "HELLO", PeerID: "peer-1"}
	msg.Seq = 1
	msg.Timestamp = time.Now().Unix()
	msg.TTL = 2
	msg.Signature, _ = signMessage(msg, peerPriv)
	data, _ := json.Marshal(msg)
	_ = engine.handleMessage(data, "1.2.3.4")
	if len(engine.Peers()) != 1 {
		t.Fatalf("expected peer added")
	}

	engine.prunePeers(base.Add(2 * time.Second))
	if len(engine.Peers()) != 0 {
		t.Fatalf("expected peer pruned")
	}
}

func TestRoutesDedup(t *testing.T) {
	table := routing.NewTable(nil)
	peerPub, _, _ := ed25519.GenerateKey(nil)
	_, localPriv, _ := ed25519.GenerateKey(nil)
	engine := NewEngine(Config{PeerID: "self", PrivateKey: localPriv, PublicKey: peerPub}, table, nil, nil, nil)
	adverts := []RouteAdvert{
		{Destination: "10.0.0.0/8", Gateway: "192.168.1.1", Interface: "eth0", Metric: 100},
	}
	engine.applyRoutes(adverts)
	engine.applyRoutes(adverts)
	if len(engine.Routes()) != 1 {
		t.Fatalf("expected deduped routes")
	}
}

func TestReplayRejected(t *testing.T) {
	table := routing.NewTable(nil)
	peerPub, peerPriv, _ := ed25519.GenerateKey(nil)
	_, localPriv, _ := ed25519.GenerateKey(nil)
	engine := NewEngine(Config{PeerID: "self", PrivateKey: localPriv, PublicKey: peerPub}, table, nil, nil, nil)
	msg := message{Type: "HELLO", PeerID: "peer-1", Seq: 7, Timestamp: time.Now().Unix(), TTL: 2}
	msg.Signature, _ = signMessage(msg, peerPriv)
	data, _ := json.Marshal(msg)
	_ = engine.handleMessage(data, "1.2.3.4")
	_ = engine.handleMessage(data, "1.2.3.4")
	if len(engine.Peers()) != 1 {
		t.Fatalf("expected peer added once")
	}
}

type mockTransport struct {
	sent [][]byte
}

func (m *mockTransport) Send(data []byte) error {
	m.sent = append(m.sent, append([]byte(nil), data...))
	return nil
}

func (m *mockTransport) Receive(ctx context.Context) ([]byte, string, error) {
	return nil, "", ctx.Err()
}

func (m *mockTransport) Close() error {
	return nil
}

func TestNextSeqIncrements(t *testing.T) {
	engine := NewEngine(Config{PeerID: "node-1"}, routing.NewTable(nil), nil, nil, nil)
	if seq := engine.nextSeq(); seq != 1 {
		t.Fatalf("expected seq 1, got %d", seq)
	}
	if seq := engine.nextSeq(); seq != 2 {
		t.Fatalf("expected seq 2, got %d", seq)
	}
}

func TestSendMessageUsesTransport(t *testing.T) {
	mt := &mockTransport{}
	engine := NewEngine(Config{PeerID: "node-1"}, routing.NewTable(nil), mt, nil, nil)
	if err := engine.sendMessage(message{Type: "HELLO", PeerID: "node-1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mt.sent) != 1 {
		t.Fatalf("expected one message sent")
	}
	if !bytes.Contains(mt.sent[0], []byte(`"HELLO"`)) {
		t.Fatalf("expected HELLO message payload")
	}
}

func TestStartUsesExistingTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mt := &mockTransport{}
	engine := NewEngine(Config{PeerID: "node-1"}, routing.NewTable(nil), mt, nil, nil)
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
