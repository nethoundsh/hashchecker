package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/nethoundsh/hashchecker/pkg/fileinfo"
	"github.com/nethoundsh/hashchecker/pkg/hasher"
	"github.com/nethoundsh/hashchecker/pkg/vtclient"
)

// NDJSON output: each line is a self-contained JSON object.
type JSONHashes struct {
	SHA256 string `json:"sha256,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	MD5    string `json:"md5,omitempty"`
	TLSH   string `json:"tlsh,omitempty"`
}

type JSONRecord struct {
	Path       string             `json:"path,omitempty"`
	File       *fileinfo.JSONMeta `json:"file,omitempty"`
	Hashes     JSONHashes         `json:"hashes"`
	LookupHash string             `json:"lookup_hash"`
	LookupAlgo string             `json:"lookup_algorithm"`
	Result     vtclient.Result    `json:"result"`
}

type JSONSummary struct {
	Path      string `json:"path"`
	Scanned   int    `json:"scanned"`
	Found     int    `json:"found"`
	Malicious int    `json:"malicious"`
}

type JSONSummaryRecord struct {
	Summary JSONSummary `json:"summary"`
}

type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, a ...any) {
	if ew.err == nil {
		_, ew.err = fmt.Fprintf(ew.w, format, a...)
	}
}

func (ew *errWriter) println(a ...any) {
	if ew.err == nil {
		_, ew.err = fmt.Fprintln(ew.w, a...)
	}
}

// PrintLookupResult prints a single lookup result in the configured format.
func PrintLookupResult(w io.Writer, path, hash, format, algo string, result vtclient.Result, hashes *hasher.Result, meta *fileinfo.Meta) error {
	switch format {
	case "json":
		return PrintJSON(w, path, hash, algo, result, hashes, meta)
	default:
		return PrintResult(w, hash, algo, result, hashes, meta)
	}
}

// PrintJSON emits a single NDJSON line for one file result.
func PrintJSON(w io.Writer, path, hash, algo string, vtResult vtclient.Result, hashes *hasher.Result, meta *fileinfo.Meta) error {
	rec := JSONRecord{
		Path:       path,
		File:       fileinfo.ToJSON(meta),
		LookupHash: hash,
		LookupAlgo: algo,
		Result:     vtResult,
	}
	if hashes != nil {
		rec.Hashes = JSONHashes{
			SHA256: hashes.SHA256,
			SHA1:   hashes.SHA1,
			MD5:    hashes.MD5,
			TLSH:   hashes.TLSH,
		}
	} else {
		switch algo {
		case "sha256":
			rec.Hashes = JSONHashes{SHA256: hash}
		case "sha1":
			rec.Hashes = JSONHashes{SHA1: hash}
		case "md5":
			rec.Hashes = JSONHashes{MD5: hash}
		}
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling JSON output: %w", err)
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

func PrintJSONSummary(w io.Writer, path string, scanned, found, malicious int) error {
	rec := JSONSummaryRecord{
		Summary: JSONSummary{
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
	_, err = fmt.Fprintln(w, string(b))
	return err
}

// PrintResult renders a color-coded summary.
func PrintResult(w io.Writer, hash, algo string, vtResult vtclient.Result, hashes *hasher.Result, meta *fileinfo.Meta) error {
	ew := &errWriter{w: w}

	if meta != nil {
		const tsFormat = "2006-01-02 15:04:05 MST"
		ew.printf("%-16s%s\n", "  File:", meta.Name)
		ew.printf("%-16s%s\n", "  Size:", meta.SizeHuman)
		ew.printf("%-16s%s\n", "  Modified:", meta.Modified.Format(tsFormat))
		if !meta.Created.IsZero() {
			ew.printf("%-16s%s\n", "  Created:", meta.Created.Format(tsFormat))
		}
		ew.printf("%-16s%s\n", "  Permissions:", meta.Permissions)
		ew.println()
	}

	if hashes != nil {
		printHashLine(ew, "SHA-256", hashes.SHA256, algo == "sha256")
		printHashLine(ew, "SHA-1", hashes.SHA1, algo == "sha1")
		printHashLine(ew, "MD5", hashes.MD5, algo == "md5")
		if hashes.TLSH != "" {
			printHashLine(ew, "TLSH", hashes.TLSH, false)
		}
	} else {
		label := "Hash (" + algoLabel(algo) + "):"
		ew.printf("%-16s%s\n", label, color.CyanString(hash))
	}

	ew.println()

	if !vtResult.Found {
		ew.println(color.YellowString("Not found in VirusTotal"))
		return ew.err
	}

	ew.printf("%-16s%s\n", "Name:", vtResult.Name)
	ew.printf("%-16s%s\n", "Reputation:", repColorInt(vtResult.Reputation))
	ew.println()

	ew.printf("%-16s%s\n", "Malicious:", redOrGreenInt(vtResult.Malicious))
	ew.printf("%-16s%s\n", "Suspicious:", yellowOrGreenInt(vtResult.Suspicious))
	ew.printf("%-16s%s\n", "Undetected:", yellowOrGreenInt(vtResult.Undetected))
	ew.printf("%-16s%s\n", "Harmless:", color.GreenString("%d", vtResult.Harmless))
	ew.println()

	switch {
	case vtResult.ThreatLabel == "":
		ew.printf("%-16s%s\n", "Threat:", "None")
	case vtResult.Malicious > 0:
		ew.printf("%-16s%s\n", "Threat:", color.RedString("%s", vtResult.ThreatLabel))
	default:
		ew.printf("%-16s%s\n", "Threat:", vtResult.ThreatLabel)
	}

	return ew.err
}

func printHashLine(ew *errWriter, label, hash string, isVTLookup bool) {
	prefix := "  "
	if isVTLookup {
		prefix = "* "
	}
	ew.printf("%s%-14s%s\n", prefix, label+":", color.CyanString(hash))
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
