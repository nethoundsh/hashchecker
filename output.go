package main

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
)

// ── JSON Output Types ───────────────────────────────────────────────
//
// These structs define the shape of our NDJSON (newline-delimited JSON)
// output. Each line of output is one JSON object — this format is easy
// to parse with tools like jq, and doesn't require buffering the entire
// result set in memory before writing.
//
// jsonRecord represents a single per-file result in JSON output mode.
// The "omitempty" tag on Path means the field is omitted from the JSON
// when empty — this happens when the user passes a raw hash instead of
// a file path, since there's no meaningful path to display.
type jsonRecord struct {
	Path      string           `json:"path,omitempty"` // file path (empty for raw hash lookups)
	Hash      string           `json:"hash"`           // hash in hex
	Algorithm string           `json:"algorithm"`      // hash algorithm used (e.g. "sha256")
	Result    VirusTotalResult `json:"result"`         // full VT result
}

// jsonSummary is the summary object emitted after scanning a directory.
type jsonSummary struct {
	Path      string `json:"path"`      // the directory that was scanned
	Scanned   int    `json:"scanned"`   // total files looked up
	Found     int    `json:"found"`     // how many VT had a report for
	Malicious int    `json:"malicious"` // how many of those were flagged as malicious
}

// jsonSummaryRecord wraps jsonSummary under a "summary" key so that
// consumers can distinguish summary lines from per-file result lines
// by checking for the presence of the "summary" key.
type jsonSummaryRecord struct {
	Summary jsonSummary `json:"summary"`
}

// printJSON emits a single NDJSON (newline-delimited JSON) line for one
// file result. NDJSON means each line is a self-contained JSON object —
// tools like jq can process them one at a time without needing the
// entire output buffered in memory.
//
// json.Marshal serializes the struct into a []byte. We convert it to a
// string for fmt.Println, which appends the newline that makes it NDJSON.
func printJSON(path, hash, algo string, vtResult VirusTotalResult) error {
	rec := jsonRecord{
		Path:      path,
		Hash:      hash,
		Algorithm: algo,
		Result:    vtResult,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling JSON output: %w", err)
	}
	fmt.Println(string(b))
	return nil
}

// printJSONSummary emits a JSON summary line after a directory scan.
// The "summary" wrapper key lets consumers distinguish this from
// per-file result lines.
func printJSONSummary(path string, scanned, found, malicious int) error {
	rec := jsonSummaryRecord{
		Summary: jsonSummary{
			Path:      path,
			Scanned:   scanned,
			Found:     found,
			Malicious: malicious,
		},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling JSON summary: %w", err)
	}
	fmt.Println(string(b))
	return nil
}

// printResult renders a human-readable, color-coded summary for a single
// VirusTotal result.
//
// The "%-16s" format specifier left-aligns the label in a 16-character
// wide column, which keeps the values neatly aligned even with the
// algorithm name in the hash label:
//
//	Hash (SHA-256): abc123...
//	Name:           malware.exe
//	Reputation:     -5
func printResult(hash, algo string, vtResult VirusTotalResult) {
	label := "Hash (" + algoLabel(algo) + "):"
	fmt.Printf("%-16s%s\n", label, color.CyanString(hash))

	// If VT doesn't recognize this hash, there's nothing else to show.
	if !vtResult.Found {
		fmt.Println(color.YellowString("Not found in VirusTotal"))
		return
	}

	fmt.Printf("%-16s%s\n", "Name:", vtResult.Name)
	fmt.Printf("%-16s%s\n", "Reputation:", repColorInt(vtResult.Reputation))
	fmt.Printf("%-16s%s\n", "Malicious:", redOrGreenInt(vtResult.Malicious))
	fmt.Printf("%-16s%s\n", "Suspicious:", yellowOrGreenInt(vtResult.Suspicious))
	fmt.Printf("%-16s%s\n", "Undetected:", yellowOrGreenInt(vtResult.Undetected))
	fmt.Printf("%-16s%s\n", "Harmless:", color.GreenString("%d", vtResult.Harmless))

	// Threat label display logic:
	// - No label at all → show "None" so the user knows it's intentionally blank
	// - Malicious + label → red to draw attention
	// - Not malicious but has a label → show it plain (informational, not alarming)
	switch {
	case vtResult.ThreatLabel == "":
		fmt.Printf("%-16s%s\n", "Threat:", "None")
	case vtResult.Malicious > 0:
		fmt.Printf("%-16s%s\n", "Threat:", color.RedString("%s", vtResult.ThreatLabel))
	default:
		fmt.Printf("%-16s%s\n", "Threat:", vtResult.ThreatLabel)
	}
}

// algoLabel returns the human-readable display name for a hash
// algorithm identifier (e.g. "sha256" → "SHA-256"). This is used in
// the text output label so users see "Hash (SHA-256):" instead of the
// raw flag value.
func algoLabel(algo string) string {
	switch algo {
	case "sha256":
		return "SHA-256"
	case "sha1":
		return "SHA-1"
	case "md5":
		return "MD5"
	default:
		return algo
	}
}

// ── Color Helper Functions ──────────────────────────────────────────
//
// These small functions centralize the color logic for different
// semantic meanings. Each one maps a numeric value to a color that
// communicates severity at a glance:
//   - Green = good / safe / zero
//   - Yellow = worth noting / ambiguous
//   - Red = bad / dangerous / non-zero

// repColorInt colors a reputation score. In VirusTotal, negative
// reputation means the community considers the file suspicious or bad.
func repColorInt(n int) string {
	if n < 0 {
		return color.RedString("%d", n)
	}
	return color.GreenString("%d", n)
}

// redOrGreenInt colors a count where any value above zero is bad
// (e.g. malicious engine count: even 1 is concerning).
func redOrGreenInt(n int) string {
	if n > 0 {
		return color.RedString("%d", n)
	}
	return color.GreenString("%d", n)
}

// yellowOrGreenInt colors a count where non-zero is noteworthy but not
// necessarily alarming (e.g. "suspicious" or "undetected" counts).
func yellowOrGreenInt(n int) string {
	if n > 0 {
		return color.YellowString("%d", n)
	}
	return color.GreenString("%d", n)
}

