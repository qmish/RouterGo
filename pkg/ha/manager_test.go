package ha

import (
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
