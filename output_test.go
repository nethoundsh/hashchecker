package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
)

func TestPrintJSON(t *testing.T) {
	t.Run("file input with all hashes", func(t *testing.T) {
		vt := VirusTotalResult{
			Found: true, Name: "test.exe", Malicious: 5, Harmless: 50,
		}
		hashes := &hashResult{
			SHA256: "abc123sha256",
			SHA1:   "abc123sha1",
			MD5:    "abc123md5",
			TLSH:   "T1AFAF4D4E6518A5B09F34A3400B0F84E82F4D9EF2C46A951441048B50C9DAA44D0A8A1",
		}
		var buf bytes.Buffer
		meta := &fileMeta{
			Name:        "test.exe",
			Size:        145408,
			SizeHuman:   "145 kB",
			Modified:    time.Date(2026, 1, 15, 9, 23, 41, 0, time.UTC),
			Created:     time.Date(2026, 1, 10, 14, 5, 12, 0, time.UTC),
			Permissions: "-rwxr-xr-x",
		}
		if err := printJSON(&buf, "/tmp/test.exe", "abc123sha256", "sha256", vt, hashes, meta); err != nil {
			t.Fatalf("printJSON error: %v", err)
		}
		stdout := buf.String()

		var rec jsonRecord
		if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &rec); err != nil {
			t.Fatalf("invalid JSON output: %v\nraw: %s", err, stdout)
		}
		if rec.Path != "/tmp/test.exe" {
			t.Fatalf("Path = %q, want %q", rec.Path, "/tmp/test.exe")
		}
		if rec.LookupHash != "abc123sha256" {
			t.Fatalf("LookupHash = %q, want %q", rec.LookupHash, "abc123sha256")
		}
		if rec.LookupAlgo != "sha256" {
			t.Fatalf("LookupAlgo = %q, want %q", rec.LookupAlgo, "sha256")
		}
		if rec.Hashes.SHA256 != "abc123sha256" {
			t.Fatalf("Hashes.SHA256 = %q, want %q", rec.Hashes.SHA256, "abc123sha256")
		}
		if rec.Hashes.SHA1 != "abc123sha1" {
			t.Fatalf("Hashes.SHA1 = %q, want %q", rec.Hashes.SHA1, "abc123sha1")
		}
		if rec.Hashes.MD5 != "abc123md5" {
			t.Fatalf("Hashes.MD5 = %q, want %q", rec.Hashes.MD5, "abc123md5")
		}
		if rec.Hashes.TLSH != "T1AFAF4D4E6518A5B09F34A3400B0F84E82F4D9EF2C46A951441048B50C9DAA44D0A8A1" {
			t.Fatalf("Hashes.TLSH = %q, want TLSH value", rec.Hashes.TLSH)
		}
		if rec.Result.Malicious != 5 {
			t.Fatalf("Result.Malicious = %d, want 5", rec.Result.Malicious)
		}
		if rec.File == nil || rec.File.Name != "test.exe" {
			t.Fatalf("File metadata missing or wrong: %+v", rec.File)
		}
		if rec.File.Created == "" {
			t.Fatalf("expected created timestamp, got %+v", rec.File)
		}
	})

	t.Run("raw hash input (nil hashes)", func(t *testing.T) {
		vt := VirusTotalResult{Found: true, Name: "raw.bin"}
		var buf bytes.Buffer
		if err := printJSON(&buf, "", "def456", "md5", vt, nil, nil); err != nil {
			t.Fatalf("printJSON error: %v", err)
		}
		stdout := buf.String()

		var rec jsonRecord
		if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &rec); err != nil {
			t.Fatalf("invalid JSON output: %v\nraw: %s", err, stdout)
		}
		// The "path" key should be absent (omitempty)
		if strings.Contains(stdout, `"path"`) {
			t.Fatalf("expected path to be omitted, got: %s", stdout)
		}
		if rec.LookupAlgo != "md5" {
			t.Fatalf("LookupAlgo = %q, want %q", rec.LookupAlgo, "md5")
		}
		if rec.Hashes.MD5 != "def456" {
			t.Fatalf("Hashes.MD5 = %q, want %q", rec.Hashes.MD5, "def456")
		}
		if rec.File != nil {
			t.Fatalf("raw hash lookup should omit file metadata, got %+v", rec.File)
		}
	})

	t.Run("file metadata omits created when unknown", func(t *testing.T) {
		vt := VirusTotalResult{Found: true, Name: "unknown.bin"}
		hashes := &hashResult{SHA256: "abc123sha256"}
		meta := &fileMeta{
			Name:        "unknown.bin",
			Size:        12,
			SizeHuman:   "12 B",
			Modified:    time.Date(2026, 1, 15, 9, 23, 41, 0, time.UTC),
			Permissions: "-rw-r--r--",
		}

		var buf bytes.Buffer
		if err := printJSON(&buf, "/tmp/unknown.bin", "abc123sha256", "sha256", vt, hashes, meta); err != nil {
			t.Fatalf("printJSON error: %v", err)
		}
		stdout := strings.TrimSpace(buf.String())
		if strings.Contains(stdout, `"created"`) {
			t.Fatalf("expected created field omitted when zero, got: %s", stdout)
		}
	})
}

func TestPrintJSONSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := printJSONSummary(&buf, "/tmp/dir", 10, 8, 3); err != nil {
		t.Fatalf("printJSONSummary error: %v", err)
	}
	stdout := buf.String()

	var rec jsonSummaryRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &rec); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, stdout)
	}
	if rec.Summary.Path != "/tmp/dir" {
		t.Fatalf("Path = %q, want %q", rec.Summary.Path, "/tmp/dir")
	}
	if rec.Summary.Scanned != 10 {
		t.Fatalf("Scanned = %d, want 10", rec.Summary.Scanned)
	}
	if rec.Summary.Found != 8 {
		t.Fatalf("Found = %d, want 8", rec.Summary.Found)
	}
	if rec.Summary.Malicious != 3 {
		t.Fatalf("Malicious = %d, want 3", rec.Summary.Malicious)
	}
}

func TestPrintResult(t *testing.T) {
	// Disable ANSI color escapes for reliable string matching.
	oldNoColor := color.NoColor
	color.NoColor = true
	defer func() { color.NoColor = oldNoColor }()

	t.Run("file input with all hashes", func(t *testing.T) {
		vt := VirusTotalResult{
			Found: true, Name: "malware.exe", Reputation: -5,
			Malicious: 42, Suspicious: 3, Undetected: 10, Harmless: 50,
			ThreatLabel: "trojan.generic",
		}
		hashes := &hashResult{
			SHA256: "abc123sha256",
			SHA1:   "abc123sha1",
			MD5:    "abc123md5",
			TLSH:   "T1AFAF4D4E6518A5B09F34A3400B0F84E82F4D9EF2C46A951441048B50C9DAA44D0A8A1",
		}
		var buf bytes.Buffer
		meta := &fileMeta{
			Name:        "malware.exe",
			Size:        145408,
			SizeHuman:   "145 kB",
			Modified:    time.Date(2026, 1, 15, 9, 23, 41, 0, time.UTC),
			Created:     time.Date(2026, 1, 10, 14, 5, 12, 0, time.UTC),
			Permissions: "-rwxr-xr-x",
		}
		if err := printResult(&buf, "abc123sha256", "sha256", vt, hashes, meta); err != nil {
			t.Fatalf("printResult error: %v", err)
		}
		stdout := buf.String()
		for _, want := range []string{
			"abc123sha256", "abc123sha1", "abc123md5",
			"SHA-256", "SHA-1", "MD5", "TLSH",
			"File:", "Size:", "Modified:", "Created:", "Permissions:",
			"malware.exe", "-5", "42", "trojan.generic",
			"*",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("output missing %q\ngot: %s", want, stdout)
			}
		}
	})

	t.Run("file input omits empty tlsh", func(t *testing.T) {
		vt := VirusTotalResult{
			Found: true, Name: "clean.exe", Reputation: 0,
			Malicious: 0, Suspicious: 0, Undetected: 12, Harmless: 50,
		}
		hashes := &hashResult{
			SHA256: "abc123sha256",
			SHA1:   "abc123sha1",
			MD5:    "abc123md5",
			TLSH:   "",
		}
		var buf bytes.Buffer
		if err := printResult(&buf, "abc123sha256", "sha256", vt, hashes, nil); err != nil {
			t.Fatalf("printResult error: %v", err)
		}
		stdout := buf.String()
		if strings.Contains(stdout, "TLSH") {
			t.Fatalf("expected TLSH line to be omitted when empty, got: %s", stdout)
		}
	})

	t.Run("raw hash input (nil hashes)", func(t *testing.T) {
		vt := VirusTotalResult{Found: false}
		var buf bytes.Buffer
		if err := printResult(&buf, "def456", "sha1", vt, nil, nil); err != nil {
			t.Fatalf("printResult error: %v", err)
		}
		stdout := buf.String()
		if !strings.Contains(stdout, "Not found") {
			t.Fatalf("expected 'Not found' message, got: %s", stdout)
		}
		if !strings.Contains(stdout, "SHA-1") {
			t.Fatalf("expected 'SHA-1' label, got: %s", stdout)
		}
		// Raw hash input should NOT show multi-hash format
		if strings.Contains(stdout, "SHA-256") {
			t.Fatalf("raw hash should not show SHA-256 line, got: %s", stdout)
		}
	})
}

func TestColorHelpers(t *testing.T) {
	// Enable color so we can check for ANSI escape codes.
	oldNoColor := color.NoColor
	color.NoColor = false
	defer func() { color.NoColor = oldNoColor }()

	t.Run("repColorInt negative is red", func(t *testing.T) {
		s := repColorInt(-5)
		if !strings.Contains(s, "\033[") {
			t.Skip("no ANSI support in this terminal")
		}
		// Red ANSI = \033[31m
		if !strings.Contains(s, "31") {
			t.Fatalf("expected red for negative, got %q", s)
		}
	})

	t.Run("repColorInt positive is green", func(t *testing.T) {
		s := repColorInt(5)
		if !strings.Contains(s, "\033[") {
			t.Skip("no ANSI support in this terminal")
		}
		// Green ANSI = \033[32m
		if !strings.Contains(s, "32") {
			t.Fatalf("expected green for positive, got %q", s)
		}
	})

	t.Run("redOrGreenInt positive is red", func(t *testing.T) {
		s := redOrGreenInt(3)
		if !strings.Contains(s, "\033[") {
			t.Skip("no ANSI support in this terminal")
		}
		if !strings.Contains(s, "31") {
			t.Fatalf("expected red for positive, got %q", s)
		}
	})

	t.Run("redOrGreenInt zero is green", func(t *testing.T) {
		s := redOrGreenInt(0)
		if !strings.Contains(s, "\033[") {
			t.Skip("no ANSI support in this terminal")
		}
		if !strings.Contains(s, "32") {
			t.Fatalf("expected green for zero, got %q", s)
		}
	})

	t.Run("yellowOrGreenInt positive is yellow", func(t *testing.T) {
		s := yellowOrGreenInt(3)
		if !strings.Contains(s, "\033[") {
			t.Skip("no ANSI support in this terminal")
		}
		// Yellow ANSI = \033[33m
		if !strings.Contains(s, "33") {
			t.Fatalf("expected yellow for positive, got %q", s)
		}
	})

	t.Run("yellowOrGreenInt zero is green", func(t *testing.T) {
		s := yellowOrGreenInt(0)
		if !strings.Contains(s, "\033[") {
			t.Skip("no ANSI support in this terminal")
		}
		if !strings.Contains(s, "32") {
			t.Fatalf("expected green for zero, got %q", s)
		}
	})
}
