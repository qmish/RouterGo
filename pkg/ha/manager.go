package ha

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	mu          sync.Mutex
	role        Role
	nodeID      string
	priority    int
	interval    time.Duration
	hold        time.Duration
	bindAddr    string
	multicast   string
	peers       []string
	statePath   string
	stateEvery  time.Duration
	lastSeen    map[string]PeerStatus
	stateProvider func() State
	stateApplier  func(State)
	httpClient  *http.Client
}

type heartbeat struct {
	NodeID   string `json:"node_id"`
	Priority int    `json:"priority"`
	Role     Role   `json:"role"`
	TS       int64  `json:"ts"`
}

func NewManager(nodeID string, priority int, interval time.Duration, hold time.Duration, bindAddr string, multicast string, peers []string, statePath string, stateEvery time.Duration, provider func() State, applier func(State)) *Manager {
	return &Manager{
		role:         RoleStandby,
		nodeID:       nodeID,
		priority:     priority,
		interval:     interval,
		hold:         hold,
		bindAddr:     bindAddr,
		multicast:    multicast,
		peers:        peers,
		statePath:    statePath,
		stateEvery:   stateEvery,
		lastSeen:     map[string]PeerStatus{},
		stateProvider: provider,
		stateApplier:  applier,
		httpClient:   &http.Client{Timeout: 3 * time.Second},
	}
}

func (m *Manager) Start(ctx context.Context) error {
	conn, err := net.ListenPacket("udp4", m.bindAddr)
	if err != nil {
		return err
	}
	maddr, err := net.ResolveUDPAddr("udp4", m.multicast)
	if err != nil {
		_ = conn.Close()
		return err
	}

	go m.recvLoop(ctx, conn)
	go m.heartbeatLoop(ctx, conn, maddr)
	go m.electionLoop(ctx)
	go m.stateSyncLoop(ctx)
	return nil
}

func (m *Manager) Role() Role {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.role
}

func (m *Manager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	peers := make([]PeerStatus, 0, len(m.lastSeen))
	for _, p := range m.lastSeen {
		peers = append(peers, p)
	}
	return map[string]any{
		"node_id":  m.nodeID,
		"role":     m.role,
		"priority": m.priority,
		"peers":    peers,
	}
}

func (m *Manager) ApplyState(state State) {
	if m.stateApplier != nil {
		m.stateApplier(state)
	}
}

func (m *Manager) recvLoop(ctx context.Context, conn net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		var hb heartbeat
		if err := json.Unmarshal(buf[:n], &hb); err != nil {
			continue
		}
		if hb.NodeID == "" || hb.NodeID == m.nodeID {
			continue
		}
		m.mu.Lock()
		m.lastSeen[hb.NodeID] = PeerStatus{
			NodeID:   hb.NodeID,
			Priority: hb.Priority,
			LastSeen: hb.TS,
		}
		m.mu.Unlock()
	}
}

func (m *Manager) heartbeatLoop(ctx context.Context, conn net.PacketConn, maddr *net.UDPAddr) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hb := heartbeat{
				NodeID:   m.nodeID,
				Priority: m.priority,
				Role:     m.Role(),
				TS:       time.Now().Unix(),
			}
			data, _ := json.Marshal(hb)
			_, _ = conn.WriteTo(data, maddr)
		}
	}
}

func (m *Manager) electionLoop(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.evaluateRole()
		}
	}
}

func (m *Manager) evaluateRole() {
	now := time.Now().Unix()
	active := true
	for _, peer := range m.lastSeen {
		if now-int64(m.hold.Seconds()) > peer.LastSeen {
			continue
		}
		if peer.Priority > m.priority {
			active = false
		}
		if peer.Priority == m.priority && strings.Compare(peer.NodeID, m.nodeID) > 0 {
			active = false
		}
	}
	m.mu.Lock()
	if active {
		m.role = RoleActive
	} else {
		m.role = RoleStandby
	}
	m.mu.Unlock()
}

func (m *Manager) stateSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(m.stateEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if m.Role() != RoleActive || m.stateProvider == nil {
				continue
			}
			state := m.stateProvider()
			m.pushState(ctx, state)
		}
	}
}

func (m *Manager) pushState(ctx context.Context, state State) {
	body, _ := json.Marshal(state)
	for _, peer := range m.peers {
		url := strings.TrimRight(peer, "/") + m.statePath
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		_, _ = m.httpClient.Do(req)
	}
}
