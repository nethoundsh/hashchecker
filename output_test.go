package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestPrintJSON(t *testing.T) {
	t.Run("with path", func(t *testing.T) {
		vt := VirusTotalResult{
			Found: true, Name: "test.exe", Malicious: 5, Harmless: 50,
		}
		stdout := captureStdout(t, func() {
			if err := printJSON("/tmp/test.exe", "abc123", "sha256", vt); err != nil {
				t.Fatalf("printJSON error: %v", err)
			}
		})

		var rec jsonRecord
		if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &rec); err != nil {
			t.Fatalf("invalid JSON output: %v\nraw: %s", err, stdout)
		}
		if rec.Path != "/tmp/test.exe" {
			t.Fatalf("Path = %q, want %q", rec.Path, "/tmp/test.exe")
		}
		if rec.Hash != "abc123" {
			t.Fatalf("Hash = %q, want %q", rec.Hash, "abc123")
		}
		if rec.Algorithm != "sha256" {
			t.Fatalf("Algorithm = %q, want %q", rec.Algorithm, "sha256")
		}
		if rec.Result.Malicious != 5 {
			t.Fatalf("Result.Malicious = %d, want 5", rec.Result.Malicious)
		}
	})

	t.Run("without path omits field", func(t *testing.T) {
		vt := VirusTotalResult{Found: true, Name: "raw.bin"}
		stdout := captureStdout(t, func() {
			if err := printJSON("", "def456", "md5", vt); err != nil {
				t.Fatalf("printJSON error: %v", err)
			}
		})

		// The "path" key should be absent (omitempty)
		if strings.Contains(stdout, `"path"`) {
			t.Fatalf("expected path to be omitted, got: %s", stdout)
		}
		// Algorithm field should be present
		if !strings.Contains(stdout, `"algorithm":"md5"`) {
			t.Fatalf("expected algorithm field, got: %s", stdout)
		}
	})
}

func TestPrintJSONSummary(t *testing.T) {
	stdout := captureStdout(t, func() {
		if err := printJSONSummary("/tmp/dir", 10, 8, 3); err != nil {
			t.Fatalf("printJSONSummary error: %v", err)
		}
	})

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

	t.Run("found with details", func(t *testing.T) {
		vt := VirusTotalResult{
			Found: true, Name: "malware.exe", Reputation: -5,
			Malicious: 42, Suspicious: 3, Undetected: 10, Harmless: 50,
			ThreatLabel: "trojan.generic",
		}
		stdout := captureStdout(t, func() {
			printResult("abc123", "sha256", vt)
		})
		for _, want := range []string{"abc123", "SHA-256", "malware.exe", "-5", "42", "trojan.generic"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("output missing %q\ngot: %s", want, stdout)
			}
		}
	})

	t.Run("not found", func(t *testing.T) {
		vt := VirusTotalResult{Found: false}
		stdout := captureStdout(t, func() {
			printResult("def456", "sha1", vt)
		})
		if !strings.Contains(stdout, "Not found") {
			t.Fatalf("expected 'Not found' message, got: %s", stdout)
		}
		if !strings.Contains(stdout, "SHA-1") {
			t.Fatalf("expected 'SHA-1' label, got: %s", stdout)
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
