package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/fatih/color"
)

// NDJSON output: each line is a self-contained JSON object.

type jsonHashes struct {
	SHA256 string `json:"sha256,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	MD5    string `json:"md5,omitempty"`
}

type jsonRecord struct {
	Path       string           `json:"path,omitempty"`
	Hashes     jsonHashes       `json:"hashes"`
	LookupHash string           `json:"lookup_hash"`
	LookupAlgo string           `json:"lookup_algorithm"`
	Result     VirusTotalResult `json:"result"`
}

type jsonSummary struct {
	Path      string `json:"path"`      // the directory that was scanned
	Scanned   int    `json:"scanned"`   // total files looked up
	Found     int    `json:"found"`     // how many VT had a report for
	Malicious int    `json:"malicious"` // how many of those were flagged as malicious
}

// jsonSummaryRecord wraps jsonSummary so consumers can distinguish
// summary lines from per-file result lines via the "summary" key.
type jsonSummaryRecord struct {
	Summary jsonSummary `json:"summary"`
}

// printLookupResult prints a single lookup result in the configured format.
// hashes is non-nil for file input (shows all three) and nil for raw hash input.
func printLookupResult(w io.Writer, path, hash string, cfg lookupConfig, result VirusTotalResult, hashes *hashResult) error {
	switch cfg.output {
	case "json":
		return printJSON(w, path, hash, cfg.algo, result, hashes)
	default:
		printResult(w, hash, cfg.algo, result, hashes)
		return nil
	}
}

// printJSON emits a single NDJSON line for one file result.
// hashes is non-nil for file input, nil for raw hash input.
func printJSON(w io.Writer, path, hash, algo string, vtResult VirusTotalResult, hashes *hashResult) error {
	rec := jsonRecord{
		Path:       path,
		LookupHash: hash,
		LookupAlgo: algo,
		Result:     vtResult,
	}
	if hashes != nil {
		rec.Hashes = jsonHashes{
			SHA256: hashes.SHA256,
			SHA1:   hashes.SHA1,
			MD5:    hashes.MD5,
		}
	} else {
		switch algo {
		case "sha256":
			rec.Hashes = jsonHashes{SHA256: hash}
		case "sha1":
			rec.Hashes = jsonHashes{SHA1: hash}
		case "md5":
			rec.Hashes = jsonHashes{MD5: hash}
		}
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling JSON output: %w", err)
	}
	fmt.Fprintln(w, string(b))
	return nil
}

func printJSONSummary(w io.Writer, path string, scanned, found, malicious int) error {
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
	fmt.Fprintln(w, string(b))
	return nil
}

// printResult renders a color-coded summary. When hashes is non-nil (file
// input), all three hash lines are shown with a * marking the VT lookup hash.
// When nil (raw hash input), a single hash line is printed.
func printResult(w io.Writer, hash, algo string, vtResult VirusTotalResult, hashes *hashResult) {
	if hashes != nil {
		printHashLine(w, "SHA-256", hashes.SHA256, algo == "sha256")
		printHashLine(w, "SHA-1", hashes.SHA1, algo == "sha1")
		printHashLine(w, "MD5", hashes.MD5, algo == "md5")
	} else {
		label := "Hash (" + algoLabel(algo) + "):"
		fmt.Fprintf(w, "%-16s%s\n", label, color.CyanString(hash))
	}

	fmt.Fprintln(w)

	if !vtResult.Found {
		fmt.Fprintln(w, color.YellowString("Not found in VirusTotal"))
		return
	}

	fmt.Fprintf(w, "%-16s%s\n", "Name:", vtResult.Name)
	fmt.Fprintf(w, "%-16s%s\n", "Reputation:", repColorInt(vtResult.Reputation))
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%-16s%s\n", "Malicious:", redOrGreenInt(vtResult.Malicious))
	fmt.Fprintf(w, "%-16s%s\n", "Suspicious:", yellowOrGreenInt(vtResult.Suspicious))
	fmt.Fprintf(w, "%-16s%s\n", "Undetected:", yellowOrGreenInt(vtResult.Undetected))
	fmt.Fprintf(w, "%-16s%s\n", "Harmless:", color.GreenString("%d", vtResult.Harmless))
	fmt.Fprintln(w)

	switch {
	case vtResult.ThreatLabel == "":
		fmt.Fprintf(w, "%-16s%s\n", "Threat:", "None")
	case vtResult.Malicious > 0:
		fmt.Fprintf(w, "%-16s%s\n", "Threat:", color.RedString("%s", vtResult.ThreatLabel))
	default:
		fmt.Fprintf(w, "%-16s%s\n", "Threat:", vtResult.ThreatLabel)
	}
}

// printHashLine prints one hash line. The VT lookup hash is marked with *.
func printHashLine(w io.Writer, label, hash string, isVTLookup bool) {
	prefix := "  "
	if isVTLookup {
		prefix = "* "
	}
	fmt.Fprintf(w, "%s%-14s%s\n", prefix, label+":", color.CyanString(hash))
}

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

// Color helpers: green=safe, yellow=noteworthy, red=bad.

func repColorInt(n int) string {
	if n < 0 {
		return color.RedString("%d", n)
	}
	return color.GreenString("%d", n)
}

func redOrGreenInt(n int) string {
	if n > 0 {
		return color.RedString("%d", n)
	}
	return color.GreenString("%d", n)
}

func yellowOrGreenInt(n int) string {
	if n > 0 {
		return color.YellowString("%d", n)
	}
	return color.GreenString("%d", n)
}
