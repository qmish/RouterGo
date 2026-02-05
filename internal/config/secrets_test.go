package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveSecretEmpty(t *testing.T) {
	if got := ResolveSecret(""); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestResolveSecretPlain(t *testing.T) {
	got := ResolveSecret("  plain  ")
	if got != "plain" {
		t.Fatalf("expected plain, got %q", got)
	}
}

func TestResolveSecretEnv(t *testing.T) {
	t.Setenv("ROUTERGO_SECRET", "s3cr3t")
	got := ResolveSecret("env:ROUTERGO_SECRET")
	if got != "s3cr3t" {
		t.Fatalf("expected env secret, got %q", got)
	}
}

func TestResolveSecretFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("  file-secret \n"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	got := ResolveSecret("file:" + path)
	if got != "file-secret" {
		t.Fatalf("expected file secret, got %q", got)
	}
}

func TestResolveSecretFileMissing(t *testing.T) {
	got := ResolveSecret("file:does-not-exist")
	if got != "" {
		t.Fatalf("expected empty for missing file, got %q", got)
	}
}
