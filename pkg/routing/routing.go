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
	mu     sync.RWMutex
	routes []Route
	sorted []Route
}

func NewTable(routes []Route) *Table {
	table := &Table{routes: routes}
	table.rebuildSorted()
	return table
}

func (t *Table) Add(route Route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes = append(t.routes, route)
	t.rebuildSorted()
}

func (t *Table) Routes() []Route {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Route, 0, len(t.routes))
	out = append(out, t.routes...)
	return out
}

func (t *Table) Lookup(dst net.IP) (Route, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, route := range t.sorted {
		if route.Destination.Contains(dst) {
			return route, true
		}
	}
	return Route{}, false
}

func (t *Table) ReplaceRoutes(routes []Route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes = routes
	t.rebuildSorted()
}

func (t *Table) RemoveRoute(match Route) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, route := range t.routes {
		if routesEqual(route, match) {
			t.routes = append(t.routes[:i], t.routes[i+1:]...)
			t.rebuildSorted()
			return true
		}
	}
	return false
}

func (t *Table) rebuildSorted() {
	t.sorted = make([]Route, 0, len(t.routes))
	t.sorted = append(t.sorted, t.routes...)
	for i := 0; i < len(t.sorted)-1; i++ {
		for j := i + 1; j < len(t.sorted); j++ {
			ai, _ := t.sorted[i].Destination.Mask.Size()
			aj, _ := t.sorted[j].Destination.Mask.Size()
			if aj > ai || (aj == ai && t.sorted[j].Metric < t.sorted[i].Metric) {
				t.sorted[i], t.sorted[j] = t.sorted[j], t.sorted[i]
			}
		}
	}
}

func routesEqual(a Route, b Route) bool {
	if a.Interface != b.Interface || a.Metric != b.Metric {
		return false
	}
	if !ipNetEqual(a.Destination, b.Destination) {
		return false
	}
	if !ipEqual(a.Gateway, b.Gateway) {
		return false
	}
	return true
}

func ipNetEqual(a net.IPNet, b net.IPNet) bool {
	if len(a.Mask) != len(b.Mask) {
		return false
	}
	for i := range a.Mask {
		if a.Mask[i] != b.Mask[i] {
			return false
		}
	}
	return ipEqual(a.IP, b.IP)
}

func ipEqual(a net.IP, b net.IP) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}
