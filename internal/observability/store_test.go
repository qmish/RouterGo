package observability

import "testing"

func TestStoreAddsAndLimits(t *testing.T) {
	store := NewStore(2)
	store.Add(Trace{ID: "a"})
	store.Add(Trace{ID: "b"})
	store.Add(Trace{ID: "c"})

	traces := store.List()
	if len(traces) != 2 {
		t.Fatalf("expected 2 traces, got %d", len(traces))
	}
	if traces[0].ID != "b" || traces[1].ID != "c" {
		t.Fatalf("unexpected trace order: %v", traces)
	}
}

func TestStoreDefaultLimit(t *testing.T) {
	store := NewStore(0)
	if store.Limit() != 1000 {
		t.Fatalf("expected default limit 1000, got %d", store.Limit())
	}
}
