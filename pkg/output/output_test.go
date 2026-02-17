package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/nethoundsh/hashchecker/pkg/fileinfo"
	"github.com/nethoundsh/hashchecker/pkg/hasher"
	"github.com/nethoundsh/hashchecker/pkg/vtclient"
)

func TestPrintJSON(t *testing.T) {
	t.Run("file input with all hashes", func(t *testing.T) {
		vt := vtclient.Result{Found: true, Name: "test.exe", Malicious: 5, Harmless: 50}
		hashes := &hasher.Result{
			SHA256: "abc123sha256",
			SHA1:   "abc123sha1",
			MD5:    "abc123md5",
			TLSH:   "T1AFAF4D4E6518A5B09F34A3400B0F84E82F4D9EF2C46A951441048B50C9DAA44D0A8A1",
		}
		var buf bytes.Buffer
		meta := &fileinfo.Meta{
			Name:        "test.exe",
			Size:        145408,
			SizeHuman:   "145 kB",
			Modified:    time.Date(2026, 1, 15, 9, 23, 41, 0, time.UTC),
			Created:     time.Date(2026, 1, 10, 14, 5, 12, 0, time.UTC),
			Permissions: "-rwxr-xr-x",
		}
		if err := PrintJSON(&buf, "/tmp/test.exe", "abc123sha256", "sha256", vt, hashes, meta); err != nil {
			t.Fatalf("PrintJSON error: %v", err)
		}

		var rec JSONRecord
		if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
			t.Fatalf("invalid JSON output: %v", err)
		}
		if rec.Path != "/tmp/test.exe" || rec.LookupHash != "abc123sha256" || rec.LookupAlgo != "sha256" {
			t.Fatalf("unexpected core fields: %+v", rec)
		}
		if rec.Hashes.SHA1 != "abc123sha1" || rec.Hashes.MD5 != "abc123md5" || rec.Hashes.TLSH == "" {
			t.Fatalf("unexpected hashes: %+v", rec.Hashes)
		}
		if rec.File == nil || rec.File.Name != "test.exe" || rec.File.Created == "" {
			t.Fatalf("unexpected file metadata: %+v", rec.File)
		}
	})

	t.Run("raw hash input (nil hashes)", func(t *testing.T) {
		vt := vtclient.Result{Found: true, Name: "raw.bin"}
		var buf bytes.Buffer
		if err := PrintJSON(&buf, "", "def456", "md5", vt, nil, nil); err != nil {
			t.Fatalf("PrintJSON error: %v", err)
		}
		stdout := buf.String()
		var rec JSONRecord
		if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &rec); err != nil {
			t.Fatalf("invalid JSON output: %v", err)
		}
		if strings.Contains(stdout, `"path"`) || rec.Hashes.MD5 != "def456" || rec.File != nil {
			t.Fatalf("unexpected raw-hash JSON output: %s", stdout)
		}
	})
}

func TestPrintJSONSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintJSONSummary(&buf, "/tmp/dir", 10, 8, 3); err != nil {
		t.Fatalf("PrintJSONSummary error: %v", err)
	}
	var rec JSONSummaryRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rec.Summary.Path != "/tmp/dir" || rec.Summary.Scanned != 10 || rec.Summary.Found != 8 || rec.Summary.Malicious != 3 {
		t.Fatalf("unexpected summary: %+v", rec.Summary)
	}
}

func TestPrintResult(t *testing.T) {
	oldNoColor := color.NoColor
	color.NoColor = true
	defer func() { color.NoColor = oldNoColor }()

	vt := vtclient.Result{
		Found: true, Name: "malware.exe", Reputation: -5,
		Malicious: 42, Suspicious: 3, Undetected: 10, Harmless: 50, ThreatLabel: "trojan.generic",
	}
	hashes := &hasher.Result{SHA256: "a", SHA1: "b", MD5: "c", TLSH: "d"}
	meta := &fileinfo.Meta{Name: "malware.exe", SizeHuman: "1 kB", Modified: time.Now(), Permissions: "-rwxr-xr-x"}
	var buf bytes.Buffer
	if err := PrintResult(&buf, "a", "sha256", vt, hashes, meta); err != nil {
		t.Fatalf("PrintResult error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"SHA-256", "SHA-1", "MD5", "TLSH", "File:", "malware.exe", "trojan.generic"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %s", want, out)
		}
	}
}

func TestColorHelpers(t *testing.T) {
	oldNoColor := color.NoColor
	color.NoColor = false
	defer func() { color.NoColor = oldNoColor }()

	if s := repColorInt(-1); !strings.Contains(s, "\033[") {
		t.Skip("no ANSI support in this terminal")
	}

	if s := redOrGreenInt(1); !strings.Contains(s, "\033[") {
		t.Fatalf("expected ANSI color for redOrGreenInt(1), got %q", s)
	}
	if s := yellowOrGreenInt(1); !strings.Contains(s, "\033[") {
		t.Fatalf("expected ANSI color for yellowOrGreenInt(1), got %q", s)
	}
}
