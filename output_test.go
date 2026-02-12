package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

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
		}
		var buf bytes.Buffer
		if err := printJSON(&buf, "/tmp/test.exe", "abc123sha256", "sha256", vt, hashes); err != nil {
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
		if rec.Result.Malicious != 5 {
			t.Fatalf("Result.Malicious = %d, want 5", rec.Result.Malicious)
		}
	})

	t.Run("raw hash input (nil hashes)", func(t *testing.T) {
		vt := VirusTotalResult{Found: true, Name: "raw.bin"}
		var buf bytes.Buffer
		if err := printJSON(&buf, "", "def456", "md5", vt, nil); err != nil {
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
		}
		var buf bytes.Buffer
		printResult(&buf, "abc123sha256", "sha256", vt, hashes)
		stdout := buf.String()
		for _, want := range []string{
			"abc123sha256", "abc123sha1", "abc123md5",
			"SHA-256", "SHA-1", "MD5",
			"malware.exe", "-5", "42", "trojan.generic",
			"*",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("output missing %q\ngot: %s", want, stdout)
			}
		}
	})

	t.Run("raw hash input (nil hashes)", func(t *testing.T) {
		vt := VirusTotalResult{Found: false}
		var buf bytes.Buffer
		printResult(&buf, "def456", "sha1", vt, nil)
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
