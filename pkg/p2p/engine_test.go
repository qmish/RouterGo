package p2p

import (
	"encoding/json"
	"testing"
	"time"

	"router-go/pkg/routing"
)

func TestHandleHelloAddsPeer(t *testing.T) {
	table := routing.NewTable(nil)
	peerCount := 0
	engine := NewEngine(Config{PeerID: "self"}, table, nil, func() { peerCount++ }, nil)

	msg := message{Type: "HELLO", PeerID: "peer-1"}
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
	engine := NewEngine(Config{PeerID: "self"}, table, nil, nil, func() { routeSync++ })

	msg := message{
		Type:   "ROUTES",
		PeerID: "peer-1",
		Routes: []RouteAdvert{
			{Destination: "10.0.0.0/8", Gateway: "192.168.1.1", Interface: "eth0", Metric: 100},
		},
	}
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
	engine := NewEngine(Config{PeerID: "self", PeerTTL: 1 * time.Second}, table, nil, nil, nil)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	engine.nowFunc = func() time.Time { return base }

	msg := message{Type: "HELLO", PeerID: "peer-1"}
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
	engine := NewEngine(Config{PeerID: "self"}, table, nil, nil, nil)
	adverts := []RouteAdvert{
		{Destination: "10.0.0.0/8", Gateway: "192.168.1.1", Interface: "eth0", Metric: 100},
	}
	engine.applyRoutes(adverts)
	engine.applyRoutes(adverts)
	if len(engine.Routes()) != 1 {
		t.Fatalf("expected deduped routes")
	}
}
