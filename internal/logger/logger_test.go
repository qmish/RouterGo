package logger

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"
)

func TestShouldLogLevels(t *testing.T) {
	tests := []struct {
		level   string
		current string
		want    bool
	}{
		{"debug", "debug", true},
		{"info", "debug", true},
		{"warn", "info", true},
		{"error", "warn", true},
		{"debug", "info", false},
		{"info", "warn", false},
		{"warn", "error", false},
		{"unknown", "error", false},
		{"error", "unknown", true},
		{"unknown", "unknown", true},
	}

	for _, tc := range tests {
		if got := shouldLog(tc.level, tc.current); got != tc.want {
			t.Fatalf("shouldLog(%q, %q)=%v, want %v", tc.level, tc.current, got, tc.want)
		}
	}
}

func TestLoggerWritesJSON(t *testing.T) {
	log := New("info")
	buf := &bytes.Buffer{}
	log.out = buf

	log.Info("hello", map[string]any{"k": "v"})

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}
	if entry["level"] != "info" {
		t.Fatalf("expected level info, got %v", entry["level"])
	}
	if entry["msg"] != "hello" {
		t.Fatalf("expected msg hello, got %v", entry["msg"])
	}
	if entry["k"] != "v" {
		t.Fatalf("expected field k=v, got %v", entry["k"])
	}
	if entry["ts"] == "" {
		t.Fatalf("expected ts to be set")
	}
}

func TestLoggerSkipsDebugBelowLevel(t *testing.T) {
	log := New("info")
	buf := &bytes.Buffer{}
	log.out = buf

	log.Debug("debug", nil)
	if buf.Len() != 0 {
		t.Fatalf("expected no output, got %q", buf.String())
	}
}

func TestLoggerHookReceivesEntry(t *testing.T) {
	log := New("info")
	log.out = io.Discard

	ch := make(chan map[string]any, 1)
	log.AddHook(func(entry map[string]any) {
		ch <- entry
	})

	log.Warn("warn-msg", map[string]any{"x": "y"})

	select {
	case entry := <-ch:
		if entry["msg"] != "warn-msg" {
			t.Fatalf("expected msg warn-msg, got %v", entry["msg"])
		}
		if entry["level"] != "warn" {
			t.Fatalf("expected level warn, got %v", entry["level"])
		}
		if entry["x"] != "y" {
			t.Fatalf("expected field x=y, got %v", entry["x"])
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected hook to be called")
	}
}
