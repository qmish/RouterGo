package ha

import (
	"net/http"
	"testing"
	"time"
)

func TestManagerEvaluateRole(t *testing.T) {
	now := time.Now().Unix()
	manager := NewManager(
		"node-1",
		100,
		2*time.Second,
		6*time.Second,
		":5356",
		"224.0.0.252:5356",
		nil,
		"/api/ha/state",
		5*time.Second,
		nil,
		nil,
	)

	manager.lastSeen["node-2"] = PeerStatus{
		NodeID:   "node-2",
		Priority: 150,
		LastSeen: now,
	}
	manager.evaluateRole()
	if manager.Role() != RoleStandby {
		t.Fatalf("expected standby when peer has higher priority")
	}

	manager.lastSeen = map[string]PeerStatus{
		"node-2": {
			NodeID:   "node-2",
			Priority: 50,
			LastSeen: now,
		},
	}
	manager.evaluateRole()
	if manager.Role() != RoleActive {
		t.Fatalf("expected active when peer has lower priority")
	}

	manager.lastSeen = map[string]PeerStatus{
		"node-2": {
			NodeID:   "node-2",
			Priority: 100,
			LastSeen: now,
		},
	}
	manager.evaluateRole()
	if manager.Role() != RoleStandby {
		t.Fatalf("expected standby when peer has same priority and higher node id")
	}

	manager.lastSeen = map[string]PeerStatus{
		"node-2": {
			NodeID:   "node-2",
			Priority: 150,
			LastSeen: now - 20,
		},
	}
	manager.evaluateRole()
	if manager.Role() != RoleActive {
		t.Fatalf("expected active when peer is expired")
	}
}

func TestManagerStatus(t *testing.T) {
	manager := NewManager(
		"node-1",
		100,
		2*time.Second,
		6*time.Second,
		":5356",
		"224.0.0.252:5356",
		nil,
		"/api/ha/state",
		5*time.Second,
		nil,
		nil,
	)
	manager.lastSeen["node-2"] = PeerStatus{
		NodeID:   "node-2",
		Priority: 150,
		LastSeen: time.Now().Unix(),
	}

	status := manager.Status()
	if status["node_id"] != "node-1" {
		t.Fatalf("expected node_id node-1, got %v", status["node_id"])
	}
	if status["role"] != RoleStandby {
		t.Fatalf("expected role standby, got %v", status["role"])
	}
	if status["priority"] != 100 {
		t.Fatalf("expected priority 100, got %v", status["priority"])
	}
	peers, ok := status["peers"].([]PeerStatus)
	if !ok || len(peers) != 1 {
		t.Fatalf("expected one peer in status")
	}
	if peers[0].NodeID != "node-2" {
		t.Fatalf("expected peer node-2, got %v", peers[0].NodeID)
	}
}

func TestManagerApplyState(t *testing.T) {
	var applied State
	manager := NewManager(
		"node-1",
		100,
		2*time.Second,
		6*time.Second,
		":5356",
		"224.0.0.252:5356",
		nil,
		"/api/ha/state",
		5*time.Second,
		nil,
		func(state State) {
			applied = state
		},
	)
	state := State{
		FirewallDefaults: map[string]string{"INPUT": "DROP"},
	}
	manager.ApplyState(state)
	if applied.FirewallDefaults["INPUT"] != "DROP" {
		t.Fatalf("expected applied state to be recorded")
	}
}

func TestManagerSetHTTPClient(t *testing.T) {
	manager := NewManager(
		"node-1",
		100,
		2*time.Second,
		6*time.Second,
		":5356",
		"224.0.0.252:5356",
		nil,
		"/api/ha/state",
		5*time.Second,
		nil,
		nil,
	)
	manager.SetHTTPClient(nil)
	manager.SetHTTPClient(&http.Client{Timeout: 2 * time.Second})
}
