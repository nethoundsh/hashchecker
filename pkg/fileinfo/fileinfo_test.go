package fileinfo

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.txt")
	if err := os.WriteFile(path, []byte("metadata test content"), 0o640); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat temp file: %v", err)
	}

	meta := New(path, fi)
	if meta == nil {
		t.Fatal("New returned nil")
	}
	if meta.Name != fi.Name() {
		t.Fatalf("Name = %q, want %q", meta.Name, fi.Name())
	}
	if meta.Size != fi.Size() {
		t.Fatalf("Size = %d, want %d", meta.Size, fi.Size())
	}
	if meta.SizeHuman == "" {
		t.Fatal("SizeHuman should not be empty")
	}
	if meta.Modified.IsZero() {
		t.Fatal("Modified should not be zero")
	}
	if meta.Permissions != fi.Mode().String() {
		t.Fatalf("Permissions = %q, want %q", meta.Permissions, fi.Mode().String())
	}
	if !meta.Created.IsZero() && meta.Created.Location() != time.UTC {
		t.Fatalf("Created should be UTC when present, got %v", meta.Created.Location())
	}
}
