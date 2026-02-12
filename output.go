package main

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
)

// NDJSON output: each line is a self-contained JSON object.

type jsonRecord struct {
	Path      string           `json:"path,omitempty"` // file path (empty for raw hash lookups)
	Hash      string           `json:"hash"`           // hash in hex
	Algorithm string           `json:"algorithm"`      // hash algorithm used (e.g. "sha256")
	Result    VirusTotalResult `json:"result"`         // full VT result
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
func printLookupResult(path, hash string, cfg lookupConfig, result VirusTotalResult) error {
	switch cfg.output {
	case "json":
		return printJSON(path, hash, cfg.algo, result)
	default:
		printResult(hash, cfg.algo, result)
		return nil
	}
}

// printJSON emits a single NDJSON line for one file result.
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

// printResult renders a color-coded summary. Labels are left-aligned
// in a 16-char column for neat alignment.
func printResult(hash, algo string, vtResult VirusTotalResult) {
	label := "Hash (" + algoLabel(algo) + "):"
	fmt.Printf("%-16s%s\n", label, color.CyanString(hash))

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

	switch {
	case vtResult.ThreatLabel == "":
		fmt.Printf("%-16s%s\n", "Threat:", "None")
	case vtResult.Malicious > 0:
		fmt.Printf("%-16s%s\n", "Threat:", color.RedString("%s", vtResult.ThreatLabel))
	default:
		fmt.Printf("%-16s%s\n", "Threat:", vtResult.ThreatLabel)
	}
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

