// hashchecker hashes files and checks them against VirusTotal.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

// VirusTotalResult holds the VirusTotal API response for a file hash.
// Found is false when the hash is not in VirusTotal (e.g. 404); otherwise
// the other fields are populated from the file report.
type VirusTotalResult struct {
	Found       bool   `json:"found"`      // true if VirusTotal has a report for this hash
	Name        string `json:"name"`       // meaningful_name from the report
	Reputation  int    `json:"reputation"` // reputation score
	Malicious   int    `json:"malicious"`  // number of engines that flagged as malicious
	Suspicious  int    `json:"suspicious"`
	Undetected  int    `json:"undetected"`
	Harmless    int    `json:"harmless"`
	ThreatLabel string `json:"threat_label"` // suggested threat label, if any
}

// freeTierDelay is the delay between API requests when -free is set (VirusTotal free API: 4 req/min).
const freeTierDelay = 15 * time.Second

func main() {
	freeMode := flag.Bool("free", false, "use free-tier rate limiting (4 requests/min)")
	output := flag.String("o", "text", "output format: text or json")
	noColor := flag.Bool("no-color", false, "disable colored output")
	noCache := flag.Bool("no-cache", false, "disable cache (don't read or write)")
	refresh := flag.Bool("refresh", false, "ignore cached results but still write new ones")
	cacheAge := flag.Int("cache-age", 7, "maximum age of cached results in days")
	flag.Parse()
	switch *output {
	case "text", "json":
		// ok
	default:
		fmt.Fprintln(os.Stderr, "invalid -o value; must be 'text' or 'json'")
		os.Exit(1)
	}

	if *output == "json" || *noColor {
		color.NoColor = true
	}

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: hashchecker [-free] [-o text|json] [-no-color] <file or SHA-256 hash or directory>")
		os.Exit(1)
	}

	var cache map[string]cacheEntry
	var cachePath string
	if !*noCache {
		var err error
		cachePath, err = getCacheFilePath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Warning: cache disabled:", err)
			cache = make(map[string]cacheEntry)
		} else {
			cache, err = loadCache(cachePath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Warning: cache disabled:", err)
			}
		}
	}
	if cache == nil {
		cache = make(map[string]cacheEntry)
	}

	flushCache := func() {
		if !*noCache && cachePath != "" {
			if err := saveCache(cachePath, cache); err != nil {
				fmt.Fprintln(os.Stderr, "Warning: failed to save cache:", err)
			}
		}
	}

	// Create shared HTTP client once so connections can be reused.
	client := &http.Client{Timeout: 15 * time.Second}

	// Read and validate API key up front so we fail fast before doing any work.
	apiKey := strings.TrimSpace(os.Getenv("VIRUSTOTAL_API_KEY"))
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "VIRUSTOTAL_API_KEY is not set")
		os.Exit(1)
	}

	arg := flag.Arg(0)

	if isHexHash(arg) {
		hash := strings.ToLower(arg)
		result, err := lookupAndPrint(client, apiKey, *output, "", hash, cache, *refresh, *cacheAge)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		if result.Found && result.Malicious > 0 {
			flushCache()
			os.Exit(2)
		}
		flushCache()
		return
	}

	fi, err := os.Stat(arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if fi.IsDir() {
		entries, err := os.ReadDir(arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		var scanned, malicious int
		firstFile := true
		for _, entry := range entries {
			if entry.IsDir() || !entry.Type().IsRegular() {
				continue
			}
			if *freeMode && !firstFile {
				time.Sleep(freeTierDelay)
			}
			firstFile = false
			fullPath := filepath.Join(arg, entry.Name())
			hash, err := hashFile(fullPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error:", fullPath, err)
				continue
			}
			if *output == "text" {
				fmt.Println(color.HiBlueString("--- %s ---", fullPath))
			}
			result, err := lookupAndPrint(client, apiKey, *output, fullPath, hash, cache, *refresh, *cacheAge)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
				continue
			}
			if result.Found {
				scanned++
				if result.Malicious > 0 {
					malicious++
				}
			}
		}
		if *output == "json" {
			if err := printJSONSummary(arg, scanned, malicious); err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
				os.Exit(1)
			}
		} else {
			maliciousStr := color.GreenString("%d", malicious)
			if malicious > 0 {
				maliciousStr = color.RedString("%d", malicious)
			}
			fmt.Printf("Scanned %d files, %s malicious\n", scanned, maliciousStr)
		}
		if malicious > 0 {
			flushCache()
			os.Exit(2)
		}
		flushCache()
		return
	}

	hash, err := hashFile(arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	result, err := lookupAndPrint(client, apiKey, *output, arg, hash, cache, *refresh, *cacheAge)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	if result.Found && result.Malicious > 0 {
		flushCache()
		os.Exit(2)
	}

	flushCache()
}

type jsonRecord struct {
	Path   string           `json:"path,omitempty"`
	Hash   string           `json:"hash"`
	Result VirusTotalResult `json:"result"`
}

type jsonSummary struct {
	Path      string `json:"path"`
	Scanned   int    `json:"scanned"`
	Malicious int    `json:"malicious"`
}

type jsonSummaryRecord struct {
	Summary jsonSummary `json:"summary"`
}

type cacheEntry struct {
	Result    VirusTotalResult `json:"result"`
	Timestamp time.Time        `json:"timestamp"`
}

// lookupAndPrint calls VirusTotal, prints the result (text or JSON), and returns it to the caller.
// This keeps the lookup+presentation pattern in one place without over-abstracting.
func lookupAndPrint(client *http.Client, apiKey, output, path, hash string, cache map[string]cacheEntry, refresh bool,
	cacheAgeDays int) (VirusTotalResult, error) {

	// Check cache first
	if !refresh {
		if entry, ok := cache[hash]; ok {
			age := time.Since(entry.Timestamp)
			if age < time.Duration(cacheAgeDays)*24*time.Hour {
				// Cache hit — use stored result, skip API call
				// ... print result and return ...
				switch output {
				case "json":
					if err := printJSON(path, hash, entry.Result); err != nil {
						return VirusTotalResult{}, err
					}
				default:
					printResult(hash, entry.Result)
				}
				return entry.Result, nil
			}
		}
	}
	result, err := checkVirusTotal(client, apiKey, hash)

	if err != nil {
		return VirusTotalResult{}, err
	}

	cache[hash] = cacheEntry{
		Result:    result,
		Timestamp: time.Now(),
	}
	switch output {
	case "json":
		if err := printJSON(path, hash, result); err != nil {
			return VirusTotalResult{}, err
		}
	default:
		printResult(hash, result)
	}
	return result, nil
}

// NDJSON format: one JSON object per line.
func printJSON(path, hash string, vtResult VirusTotalResult) error {
	rec := jsonRecord{
		Path:   path,
		Hash:   hash,
		Result: vtResult,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func printJSONSummary(path string, scanned, malicious int) error {
	rec := jsonSummaryRecord{
		Summary: jsonSummary{
			Path:      path,
			Scanned:   scanned,
			Malicious: malicious,
		},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// printResult prints a human-readable summary for a VirusTotalResult.
func printResult(hash string, vtResult VirusTotalResult) {
	fmt.Printf("%-12s%s\n", "Hash:", color.CyanString(hash))
	if !vtResult.Found {
		fmt.Println(color.YellowString("Not found in VirusTotal"))
		return
	}
	fmt.Printf("%-12s%s\n", "Name:", vtResult.Name)
	fmt.Printf("%-12s%s\n", "Reputation:", repColorInt(vtResult.Reputation))
	fmt.Printf("%-12s%s\n", "Malicious:", redOrGreenInt(vtResult.Malicious))
	fmt.Printf("%-12s%s\n", "Suspicious:", yellowOrGreenInt(vtResult.Suspicious))
	fmt.Printf("%-12s%s\n", "Undetected:", yellowOrGreenInt(vtResult.Undetected))
	fmt.Printf("%-12s%s\n", "Harmless:", color.GreenString("%d", vtResult.Harmless))
	switch {
	case vtResult.ThreatLabel == "":
		// No label from VT; explicitly show that there's nothing to report.
		fmt.Printf("%-12s%s\n", "Threat:", "None")
	case vtResult.Malicious > 0:
		// Malicious with a label: highlight in red.
		fmt.Printf("%-12s%s\n", "Threat:", color.RedString("%s", vtResult.ThreatLabel))
	default:
		// Non-malicious file that still has a VT label: show it without extra emphasis.
		fmt.Printf("%-12s%s\n", "Threat:", vtResult.ThreatLabel)
	}
}

// isHexHash reports whether s is a valid SHA-256 hash in hex (64 hex chars = 32 bytes).
// Uses hex.DecodeString so both length and character validity are checked in one call.
func isHexHash(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32
}

// hashFile opens the file at filePath, computes its SHA-256 hash, and returns
// the hash as a hex string. The file is closed when the function returns.
func hashFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// checkVirusTotal looks up the given SHA-256 hash (hex) in VirusTotal's API
// and returns a report. 404 is treated as "not found" (Found: false); non-200
// responses return an error that includes part of the response body. client is
// reused for connection pooling.
func checkVirusTotal(client *http.Client, apiKey, hash string) (VirusTotalResult, error) {
	req, err := http.NewRequest("GET", "https://www.virustotal.com/api/v3/files/"+hash, nil)
	if err != nil {
		return VirusTotalResult{}, err
	}
	req.Header.Set("x-apikey", apiKey)

	response, err := client.Do(req)
	if err != nil {
		return VirusTotalResult{}, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return VirusTotalResult{}, err
	}

	if response.StatusCode == 404 {
		return VirusTotalResult{Found: false}, nil
	}
	if response.StatusCode != 200 {
		// Include response body in error (e.g. rate limit or API message).
		bodyStr := truncateRunes(string(body), 200)
		return VirusTotalResult{}, fmt.Errorf("unexpected status: %d: %s", response.StatusCode, bodyStr)
	}

	// Matches VirusTotal API v3 file report JSON shape.
	var result struct {
		Data struct {
			Attributes struct {
				MeaningfulName    string `json:"meaningful_name"`
				Reputation        int    `json:"reputation"`
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
				PopularThreatClassification struct {
					SuggestedThreatLabel string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return VirusTotalResult{}, fmt.Errorf("parsing response: %w", err)
	}

	stats := result.Data.Attributes.LastAnalysisStats
	return VirusTotalResult{
		Found:       true,
		Name:        result.Data.Attributes.MeaningfulName,
		Reputation:  result.Data.Attributes.Reputation,
		Malicious:   stats.Malicious,
		Suspicious:  stats.Suspicious,
		Undetected:  stats.Undetected,
		Harmless:    stats.Harmless,
		ThreatLabel: result.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel,
	}, nil
}

// truncateRunes returns s truncated to at most max runes, adding "..." if truncated.
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}

// repColorInt colors a reputation score: negative = red (bad), zero/positive = green.
func repColorInt(n int) string {
	if n < 0 {
		return color.RedString("%d", n)
	}
	return color.GreenString("%d", n)
}

// redOrGreenInt colors a count where any non-zero value is bad: >0 = red, 0 = green.
func redOrGreenInt(n int) string {
	if n > 0 {
		return color.RedString("%d", n)
	}
	return color.GreenString("%d", n)
}

// yellowOrGreenInt colors a neutral-or-warning count: >0 = yellow, 0 = green.
func yellowOrGreenInt(n int) string {
	if n > 0 {
		return color.YellowString("%d", n)
	}
	return color.GreenString("%d", n)
}

// small helper function to get the cache file path
func getCacheFilePath() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, "hashchecker", "results.json"), nil
}
func loadCache(path string) (map[string]cacheEntry, error) {
	cache := make(map[string]cacheEntry)
	cacheFile, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return cache, nil
	}
	if err != nil {
		return nil, err
	}
	defer cacheFile.Close()
	if err := json.NewDecoder(cacheFile).Decode(&cache); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: corrupt cache file, starting fresh")
		return make(map[string]cacheEntry), nil
	}
	return cache, nil
}

func saveCache(path string, cache map[string]cacheEntry) error {
	// Step 1: create the parent directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	// Step 2: serialize the cache map to JSON
	jsonBytes, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	// Step 3: write the JSON bytes to the file
	if err := os.WriteFile(path, jsonBytes, 0o600); err != nil {
		return err
	}
	return nil
}
