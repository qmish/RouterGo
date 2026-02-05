package observability

import "sync"

type Trace struct {
	ID         string `json:"id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	DurationMs int64  `json:"duration_ms"`
	Timestamp  int64  `json:"timestamp"`
	ClientIP   string `json:"client_ip,omitempty"`
}

type Store struct {
	mu     sync.Mutex
	limit  int
	traces []Trace
}

func NewStore(limit int) *Store {
	if limit <= 0 {
		limit = 1000
	}
	return &Store{
		limit:  limit,
		traces: make([]Trace, 0, limit),
	}
}

func (s *Store) Add(trace Trace) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.traces = append(s.traces, trace)
	if len(s.traces) > s.limit {
		s.traces = append([]Trace{}, s.traces[len(s.traces)-s.limit:]...)
	}
}

func (s *Store) List() []Trace {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Trace, 0, len(s.traces))
	out = append(out, s.traces...)
	return out
}

func (s *Store) Limit() int {
	return s.limit
}
