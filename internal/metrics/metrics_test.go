package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsSnapshot(t *testing.T) {
	m := New()
	m.IncPackets()
	m.AddBytes(150)
	m.IncErrors()
	m.IncDrops()
	m.IncDropReason("firewall")
	m.IncDropReason("qos")
	m.IncDropReason("firewall")
	m.IncQoSDrop("realtime")
	m.IncQoSDrop("realtime")
	m.IncRxPackets()
	m.IncTxPackets()
	m.IncTxPackets()
	m.IncIDSAlert()
	m.IncIDSDrop()
	m.IncIDSAlertType("SIGNATURE")
	m.IncIDSAlertRule("test-rule")
	m.IncConfigApply()
	m.IncConfigRollback()
	m.IncConfigApplyFailed()
	m.IncP2PPeer()
	m.IncP2PRouteSynced()
	m.IncProxyCacheHit()
	m.IncProxyCacheMiss()
	m.IncProxyCompress()

	s := m.Snapshot()
	if s.Packets != 1 {
		t.Fatalf("expected packets 1, got %d", s.Packets)
	}
	if s.Bytes != 150 {
		t.Fatalf("expected bytes 150, got %d", s.Bytes)
	}
	if s.Errors != 1 {
		t.Fatalf("expected errors 1, got %d", s.Errors)
	}
	if s.Drops != 6 {
		t.Fatalf("expected drops 6, got %d", s.Drops)
	}
	if s.DropsByReason["firewall"] != 2 {
		t.Fatalf("expected firewall drops 2, got %d", s.DropsByReason["firewall"])
	}
	if s.DropsByReason["qos"] != 3 {
		t.Fatalf("expected qos drops 3, got %d", s.DropsByReason["qos"])
	}
	if s.QoSDropsByClass["realtime"] != 2 {
		t.Fatalf("expected qos drops realtime 2, got %d", s.QoSDropsByClass["realtime"])
	}
	if s.RxPackets != 1 {
		t.Fatalf("expected rx packets 1, got %d", s.RxPackets)
	}
	if s.TxPackets != 2 {
		t.Fatalf("expected tx packets 2, got %d", s.TxPackets)
	}
	if s.IDSAlerts != 1 {
		t.Fatalf("expected ids alerts 1, got %d", s.IDSAlerts)
	}
	if s.IDSDrops != 1 {
		t.Fatalf("expected ids drops 1, got %d", s.IDSDrops)
	}
	if s.IDSAlertsByType["SIGNATURE"] != 1 {
		t.Fatalf("expected ids alerts by type 1, got %d", s.IDSAlertsByType["SIGNATURE"])
	}
	if s.IDSAlertsByRule["test-rule"] != 1 {
		t.Fatalf("expected ids alerts by rule 1, got %d", s.IDSAlertsByRule["test-rule"])
	}
	if s.ConfigApply != 1 {
		t.Fatalf("expected config apply 1, got %d", s.ConfigApply)
	}
	if s.ConfigRollback != 1 {
		t.Fatalf("expected config rollback 1, got %d", s.ConfigRollback)
	}
	if s.ConfigApplyFailed != 1 {
		t.Fatalf("expected config apply failed 1, got %d", s.ConfigApplyFailed)
	}
	if s.P2PPeers != 1 {
		t.Fatalf("expected p2p peers 1, got %d", s.P2PPeers)
	}
	if s.P2PRoutesSynced != 1 {
		t.Fatalf("expected p2p routes synced 1, got %d", s.P2PRoutesSynced)
	}
	if s.ProxyCacheHits != 1 {
		t.Fatalf("expected proxy cache hits 1, got %d", s.ProxyCacheHits)
	}
	if s.ProxyCacheMiss != 1 {
		t.Fatalf("expected proxy cache miss 1, got %d", s.ProxyCacheMiss)
	}
	if s.ProxyCompress != 1 {
		t.Fatalf("expected proxy compress 1, got %d", s.ProxyCompress)
	}
}


func TestIncDropReasonIncrementsCounters(t *testing.T) {
	m := NewWithRegistry(prometheus.NewRegistry())
	m.IncDropReason("firewall")

	s := m.Snapshot()
	if s.Drops != 1 {
		t.Fatalf("expected drops 1, got %d", s.Drops)
	}
	if s.DropsByReason["firewall"] != 1 {
		t.Fatalf("expected firewall drop reason 1, got %d", s.DropsByReason["firewall"])
	}
}

func TestIncDropReasonCachedCounters(t *testing.T) {
	m := NewWithRegistry(prometheus.NewRegistry())
	m.IncDropReason("parse")
	m.IncDropReason("ids")

	s := m.Snapshot()
	if s.Drops != 2 {
		t.Fatalf("expected drops 2, got %d", s.Drops)
	}
	if s.DropsByReason["parse"] != 1 {
		t.Fatalf("expected parse drop reason 1, got %d", s.DropsByReason["parse"])
	}
	if s.DropsByReason["ids"] != 1 {
		t.Fatalf("expected ids drop reason 1, got %d", s.DropsByReason["ids"])
	}
}

func TestSnapshotIncludesCommonDropReasons(t *testing.T) {
	m := NewWithRegistry(prometheus.NewRegistry())

	s := m.Snapshot()
	if _, ok := s.DropsByReason["parse"]; !ok {
		t.Fatalf("expected parse drop reason to be present")
	}
	if _, ok := s.DropsByReason["ids"]; !ok {
		t.Fatalf("expected ids drop reason to be present")
	}
	if _, ok := s.DropsByReason["firewall"]; !ok {
		t.Fatalf("expected firewall drop reason to be present")
	}
	if _, ok := s.DropsByReason["qos"]; !ok {
		t.Fatalf("expected qos drop reason to be present")
	}
}
