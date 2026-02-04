//go:build windows

package platform

import (
	"errors"
	"testing"
)

func TestNewPacketIOWindowsNotSupported(t *testing.T) {
	_, err := NewPacketIO(Options{})
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("expected ErrNotSupported, got %v", err)
	}
}
