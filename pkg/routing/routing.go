package routing

import (
	"net"
	"sync"
)

type Route struct {
	Destination net.IPNet
	Gateway     net.IP
	Interface   string
	Metric      int
}

type Table struct {
	mu     sync.Mutex
	routes []Route
}

func NewTable(routes []Route) *Table {
	return &Table{routes: routes}
}

func (t *Table) Add(route Route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes = append(t.routes, route)
}

func (t *Table) Routes() []Route {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Route, 0, len(t.routes))
	out = append(out, t.routes...)
	return out
}

func (t *Table) Lookup(dst net.IP) (Route, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var (
		best       Route
		bestMatch  = -1
		foundMatch bool
	)
	for _, route := range t.routes {
		if route.Destination.Contains(dst) {
			ones, _ := route.Destination.Mask.Size()
			if ones > bestMatch || (ones == bestMatch && (route.Metric < best.Metric || !foundMatch)) {
				best = route
				bestMatch = ones
				foundMatch = true
			}
		}
	}
	return best, foundMatch
}

func (t *Table) ReplaceRoutes(routes []Route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes = routes
}
