package metrics

import "testing"

func TestMetricsSnapshot(t *testing.T) {
	m := New()
	m.IncPackets()
	m.AddBytes(150)
	m.IncErrors()

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
}
