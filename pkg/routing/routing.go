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
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Route, 0, len(t.routes))
	out = append(out, t.routes...)
	return out
}

func (t *Table) Lookup(dst net.IP) (Route, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
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
