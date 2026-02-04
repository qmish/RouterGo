package p2p

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"

	"router-go/pkg/routing"
)

type Peer struct {
	ID       string    `json:"id"`
	Addr     string    `json:"addr"`
	LastSeen time.Time `json:"last_seen"`
}

type RouteAdvert struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
}

type Config struct {
	PeerID        string
	Discovery     bool
	SyncInterval  time.Duration
	ListenAddr    string
	MulticastAddr string
}

type Engine struct {
	mu           sync.Mutex
	cfg          Config
	peers        map[string]Peer
	routes       []routing.Route
	table        *routing.Table
	transport    Transport
	onPeer       func()
	onRouteSync  func()
}

type message struct {
	Type   string        `json:"type"`
	PeerID string        `json:"peer_id"`
	Routes []RouteAdvert `json:"routes,omitempty"`
}

func NewEngine(cfg Config, table *routing.Table, transport Transport, onPeer func(), onRouteSync func()) *Engine {
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 10 * time.Second
	}
	return &Engine{
		cfg:       cfg,
		peers:     map[string]Peer{},
		routes:    nil,
		table:     table,
		transport: transport,
		onPeer:    onPeer,
		onRouteSync: onRouteSync,
	}
}

func (e *Engine) Start(ctx context.Context) error {
	if e.transport == nil {
		t, err := NewUDPTransport(e.cfg.ListenAddr, e.cfg.MulticastAddr)
		if err != nil {
			return err
		}
		e.transport = t
	}

	go e.receiveLoop(ctx)
	if e.cfg.Discovery {
		go e.helloLoop(ctx)
	}
	go e.syncLoop(ctx)
	return nil
}

func (e *Engine) Peers() []Peer {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Peer, 0, len(e.peers))
	for _, peer := range e.peers {
		out = append(out, peer)
	}
	return out
}

func (e *Engine) Routes() []routing.Route {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]routing.Route, 0, len(e.routes))
	out = append(out, e.routes...)
	return out
}

func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.peers = map[string]Peer{}
	e.routes = nil
}

func (e *Engine) receiveLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		data, addr, err := e.transport.Receive(ctx)
		if err != nil {
			continue
		}
		_ = e.handleMessage(data, addr)
	}
}

func (e *Engine) helloLoop(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.SyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = e.sendHello()
		}
	}
}

func (e *Engine) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.SyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = e.sendRoutes()
		}
	}
}

func (e *Engine) sendHello() error {
	msg := message{
		Type:   "HELLO",
		PeerID: e.cfg.PeerID,
	}
	return e.sendMessage(msg)
}

func (e *Engine) sendRoutes() error {
	routes := e.table.Routes()
	adverts := make([]RouteAdvert, 0, len(routes))
	for _, route := range routes {
		adverts = append(adverts, RouteAdvert{
			Destination: route.Destination.String(),
			Gateway:     route.Gateway.String(),
			Interface:   route.Interface,
			Metric:      route.Metric,
		})
	}
	msg := message{
		Type:   "ROUTES",
		PeerID: e.cfg.PeerID,
		Routes: adverts,
	}
	return e.sendMessage(msg)
}

func (e *Engine) sendMessage(msg message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return e.transport.Send(data)
}

func (e *Engine) handleMessage(data []byte, addr string) error {
	var msg message
	if err := json.Unmarshal(data, &msg); err != nil {
		return err
	}
	switch msg.Type {
	case "HELLO":
		e.addPeer(msg.PeerID, addr)
	case "ROUTES":
		e.applyRoutes(msg.Routes)
	}
	return nil
}

func (e *Engine) addPeer(id string, addr string) {
	if id == "" || id == e.cfg.PeerID {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, exists := e.peers[id]
	e.peers[id] = Peer{
		ID:       id,
		Addr:     addr,
		LastSeen: time.Now(),
	}
	if !exists && e.onPeer != nil {
		e.onPeer()
	}
}

func (e *Engine) applyRoutes(adverts []RouteAdvert) {
	added := 0
	for _, adv := range adverts {
		_, dst, err := net.ParseCIDR(adv.Destination)
		if err != nil {
			continue
		}
		gw := net.ParseIP(adv.Gateway)
		route := routing.Route{
			Destination: *dst,
			Gateway:     gw,
			Interface:   adv.Interface,
			Metric:      adv.Metric,
		}
		if !routeExists(e.table.Routes(), route) {
			e.table.Add(route)
			added++
		}
		e.mu.Lock()
		e.routes = append(e.routes, route)
		e.mu.Unlock()
	}
	if added > 0 && e.onRouteSync != nil {
		for i := 0; i < added; i++ {
			e.onRouteSync()
		}
	}
}

func routeExists(routes []routing.Route, route routing.Route) bool {
	for _, r := range routes {
		if r.Destination.String() == route.Destination.String() &&
			r.Gateway.String() == route.Gateway.String() &&
			r.Interface == route.Interface &&
			r.Metric == route.Metric {
			return true
		}
	}
	return false
}
