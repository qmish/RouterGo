//go:build linux

package platform

import "testing"

func TestNewPacketIOInvalidInterface(t *testing.T) {
	_, err := NewPacketIO(Options{})
	if err == nil {
		t.Fatalf("expected error for empty interface name")
	}
}
