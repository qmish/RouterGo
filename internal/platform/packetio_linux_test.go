//go:build linux

package platform

import (
	"context"
	"errors"
	"testing"
)

func TestNewPacketIOLinuxStub(t *testing.T) {
	io, err := NewPacketIO(Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if io == nil {
		t.Fatalf("expected packet io instance")
	}

	_, err = io.ReadPacket(context.Background())
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("expected ErrNotSupported, got %v", err)
	}
}
