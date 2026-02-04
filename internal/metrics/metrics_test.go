package metrics

import "testing"

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
	m.IncConfigApply()
	m.IncConfigRollback()
	m.IncConfigApplyFailed()

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
	if s.ConfigApply != 1 {
		t.Fatalf("expected config apply 1, got %d", s.ConfigApply)
	}
	if s.ConfigRollback != 1 {
		t.Fatalf("expected config rollback 1, got %d", s.ConfigRollback)
	}
	if s.ConfigApplyFailed != 1 {
		t.Fatalf("expected config apply failed 1, got %d", s.ConfigApplyFailed)
	}
}
