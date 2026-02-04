package p2p

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/hex"
	"net"
	"strconv"
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
	PeerTTL       time.Duration
	ListenAddr    string
	MulticastAddr string
	PrivateKey    ed25519.PrivateKey
	PublicKey     ed25519.PublicKey
}

type Engine struct {
	mu          sync.Mutex
	cfg         Config
	peers       map[string]Peer
	routes      []routing.Route
	routeSet    map[string]struct{}
	replayGuard map[string]map[uint64]struct{}
	seq         uint64
	table       *routing.Table
	transport   Transport
	onPeer      func()
	onRouteSync func()
	nowFunc     func() time.Time
}

type message struct {
	Type      string        `json:"type"`
	PeerID    string        `json:"peer_id"`
	Seq       uint64        `json:"seq"`
	Timestamp int64         `json:"ts"`
	TTL       int           `json:"ttl"`
	Routes    []RouteAdvert `json:"routes,omitempty"`
	Signature string        `json:"sig,omitempty"`
}

func NewEngine(cfg Config, table *routing.Table, transport Transport, onPeer func(), onRouteSync func()) *Engine {
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 10 * time.Second
	}
	if cfg.PeerTTL == 0 {
		cfg.PeerTTL = 3 * cfg.SyncInterval
	}
	return &Engine{
		cfg:         cfg,
		peers:       map[string]Peer{},
		routes:      nil,
		routeSet:    map[string]struct{}{},
		replayGuard: map[string]map[uint64]struct{}{},
		table:       table,
		transport:   transport,
		onPeer:      onPeer,
		onRouteSync: onRouteSync,
		nowFunc:     time.Now,
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
	e.routeSet = map[string]struct{}{}
	e.replayGuard = map[string]map[uint64]struct{}{}
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
			e.prunePeers(e.nowFunc())
		}
	}
}

func (e *Engine) sendHello() error {
	return e.sendMessage(message{
		Type:   "HELLO",
		PeerID: e.cfg.PeerID,
	})
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
	return e.sendMessage(message{
		Type:   "ROUTES",
		PeerID: e.cfg.PeerID,
		Routes: adverts,
	})
}

func (e *Engine) sendMessage(msg message) error {
	msg.Seq = e.nextSeq()
	msg.Timestamp = e.nowFunc().Unix()
	msg.TTL = 2
	signature, err := signMessage(msg, e.cfg.PrivateKey)
	if err != nil {
		return err
	}
	msg.Signature = signature
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
	if msg.TTL <= 0 {
		return nil
	}
	if !verifyMessage(msg, e.cfg.PublicKey) {
		return nil
	}
	msg.TTL--
	if e.isReplay(msg.PeerID, msg.Seq) {
		return nil
	}
	e.rememberSeq(msg.PeerID, msg.Seq)
	switch msg.Type {
	case "HELLO":
		e.addPeer(msg.PeerID, addr)
	case "ROUTES":
		e.addPeer(msg.PeerID, addr)
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
		LastSeen: e.nowFunc(),
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
		key := routeKey(route)
		e.mu.Lock()
		if _, exists := e.routeSet[key]; !exists {
			e.routeSet[key] = struct{}{}
			e.routes = append(e.routes, route)
		}
		e.mu.Unlock()
	}
	if added > 0 && e.onRouteSync != nil {
		for i := 0; i < added; i++ {
			e.onRouteSync()
		}
	}
}

func (e *Engine) prunePeers(now time.Time) {
	if e.cfg.PeerTTL == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, peer := range e.peers {
		if now.Sub(peer.LastSeen) > e.cfg.PeerTTL {
			delete(e.peers, id)
		}
	}
}

func (e *Engine) nextSeq() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	return e.seq
}

func (e *Engine) isReplay(peerID string, seq uint64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.replayGuard[peerID]; !ok {
		return false
	}
	_, exists := e.replayGuard[peerID][seq]
	return exists
}

func (e *Engine) rememberSeq(peerID string, seq uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.replayGuard[peerID]; !ok {
		e.replayGuard[peerID] = map[uint64]struct{}{}
	}
	e.replayGuard[peerID][seq] = struct{}{}
	if len(e.replayGuard[peerID]) > 1000 {
		e.replayGuard[peerID] = map[uint64]struct{}{}
	}
}

func signMessage(msg message, key ed25519.PrivateKey) (string, error) {
	if len(key) == 0 {
		return "", nil
	}
	payload := signaturePayload(msg)
	sig := ed25519.Sign(key, payload)
	return hex.EncodeToString(sig), nil
}

func verifyMessage(msg message, pub ed25519.PublicKey) bool {
	if len(pub) == 0 {
		return true
	}
	if msg.Signature == "" {
		return false
	}
	raw, err := hex.DecodeString(msg.Signature)
	if err != nil {
		return false
	}
	payload := signaturePayload(msg)
	return ed25519.Verify(pub, payload, raw)
}

func signaturePayload(msg message) []byte {
	msg.Signature = ""
	b, _ := json.Marshal(msg)
	return b
}

func routeKey(route routing.Route) string {
	return route.Destination.String() + "|" + route.Gateway.String() + "|" + route.Interface + "|" + strconv.Itoa(route.Metric)
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
