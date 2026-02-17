# Implementation Plan: Code Review Fixes

This plan addresses all issues found during code review, in priority order.
Each change includes the exact files, line numbers, and code to write.

---

## Change 1 (P1): Fix `processFileToOutput` to accept `fileJob` directly

**Why:** Currently `processFileToOutput` takes a bare `path string` and returns a `workerOutput` with `index: 0`. The caller in `RunDir` has to patch `out.index = job.index` after the fact. If someone reuses `processFileToOutput` elsewhere and forgets to set the index, `OrderedPool`'s resequencing logic silently puts every result at index 0 and output order breaks. This is the same pattern `processHashToOutput` already uses (it takes `hashJob` directly and sets `index: job.index` inside).

**File:** `internal/runner/runner.go`

### Step 1a: Change the function signature

Find `processFileToOutput` (line 156). Change its signature from:

```go
func processFileToOutput(path string, cfg vtclient.LookupConfig) workerOutput {
```

to:

```go
func processFileToOutput(job fileJob, cfg vtclient.LookupConfig) workerOutput {
```

### Step 1b: Use `job.path` and `job.index` inside the function

Replace every reference to `path` inside the function body with `job.path`. There are 7 occurrences of `path` inside the function body (lines 159, 162, 163, 165, 167, 169, 177).

Then update the final return statement (line 181) to include `index: job.index`:

```go
return workerOutput{
    index:  job.index,   // ADD THIS LINE
    label:  job.path,
    output: buf.Bytes(),
    result: fileResult{
        looked:    true,
        found:     result.Found,
        malicious: result.Found && result.Malicious > 0,
    },
}
```

Also make sure all the early `return workerOutput{...}` error returns (lines 163, 169, 175, 178) include `index: job.index`. For example:

```go
return workerOutput{index: job.index, label: job.path, output: buf.Bytes(), err: err}
```

### Step 1c: Simplify the caller in `RunDir`

In `RunDir` (lines 348-353), the `OrderedPool` process function currently reads:

```go
func(job fileJob) workerOutput {
    out := processFileToOutput(job.path, cfg)
    out.index = job.index
    return out
},
```

Simplify to:

```go
func(job fileJob) workerOutput {
    return processFileToOutput(job, cfg)
},
```

---

## Change 2 (P1): Extract duplicated summary printing

**Why:** `RunDir` (lines 377-387) and `RunHashList` (lines 313-322) have nearly identical summary-printing blocks. The only difference is the unit word ("files"/"file" vs "hashes"/"hash"). Extracting this reduces duplication and ensures future summary format changes happen in one place.

**File:** `internal/runner/runner.go`

### Step 2a: Add the helper function

Add this function anywhere in the file (suggestion: right before `RunHashList`, around line 255):

```go
// printTextSummary prints the human-readable summary line.
// unitSingular/unitPlural control the noun (e.g. "file"/"files" or "hash"/"hashes").
func printTextSummary(looked, found, malicious int, unitSingular, unitPlural string) {
	maliciousStr := color.GreenString("%d", malicious)
	if malicious > 0 {
		maliciousStr = color.RedString("%d", malicious)
	}
	unit := unitPlural
	if looked == 1 {
		unit = unitSingular
	}
	_, _ = fmt.Fprintf(os.Stdout, "Checked %d %s, %d found in VirusTotal, %s malicious\n",
		looked, unit, found, maliciousStr)
}
```

### Step 2b: Replace the block in `RunHashList`

Replace lines 313-321 (the `else` branch in `RunHashList`):

```go
} else {
    maliciousStr := color.GreenString("%d", malicious)
    if malicious > 0 {
        maliciousStr = color.RedString("%d", malicious)
    }
    hashWord := "hashes"
    if looked == 1 {
        hashWord = "hash"
    }
    _, _ = fmt.Fprintf(os.Stdout, "Checked %d %s, %d found in VirusTotal, %s malicious\n", looked, hashWord, found, maliciousStr)
}
```

With:

```go
} else {
    printTextSummary(looked, found, malicious, "hash", "hashes")
}
```

### Step 2c: Replace the block in `RunDir`

Replace lines 378-387 (the `else` branch in `RunDir`):

```go
} else {
    maliciousStr := color.GreenString("%d", malicious)
    if malicious > 0 {
        maliciousStr = color.RedString("%d", malicious)
    }
    fileWord := "files"
    if looked == 1 {
        fileWord = "file"
    }
    _, _ = fmt.Fprintf(os.Stdout, "Checked %d %s, %d found in VirusTotal, %s malicious\n", looked, fileWord, found, maliciousStr)
}
```

With:

```go
} else {
    printTextSummary(looked, found, malicious, "file", "files")
}
```

---

## Change 3 (P1): Add `internal/runner/runner_test.go`

**Why:** `OrderedPool` is ~70 lines of non-trivial concurrency code with channels, goroutines, and ordered resequencing logic. It's currently only tested indirectly through end-to-end tests in `main_test.go`. Direct unit tests document the contract and catch regressions faster.

**File:** `internal/runner/runner_test.go` (new file)

**Key insight:** `OrderedPool` and `workerOutput` are package-private. The test file must be in `package runner` to access them.

### Step 3a: Create the test file

Create `internal/runner/runner_test.go` with these tests:

```go
package runner

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestOrderedPoolOutputOrder verifies that results come out in input order
// regardless of which worker finishes first.
func TestOrderedPoolOutputOrder(t *testing.T) {
	jobs := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	var got []int
	err := OrderedPool(context.Background(), 4, jobs,
		func(j int) workerOutput {
			return workerOutput{index: j, label: ""}
		},
		func(out workerOutput) {
			got = append(got, out.index)
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(jobs) {
		t.Fatalf("got %d results, want %d", len(got), len(jobs))
	}
	for i, v := range got {
		if v != i {
			t.Fatalf("result[%d] = %d, want %d (output not in order)", i, v, i)
		}
	}
}

// TestOrderedPoolSingleWorker exercises the sequential fast-path
// (workers <= 1 short-circuits to a simple loop).
func TestOrderedPoolSingleWorker(t *testing.T) {
	jobs := []int{0, 1, 2}
	var got []int
	err := OrderedPool(context.Background(), 1, jobs,
		func(j int) workerOutput {
			return workerOutput{index: j}
		},
		func(out workerOutput) {
			got = append(got, out.index)
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3", len(got))
	}
	for i, v := range got {
		if v != i {
			t.Fatalf("result[%d] = %d, want %d", i, v, i)
		}
	}
}

// TestOrderedPoolSingleJob verifies the single-job fast-path works.
func TestOrderedPoolSingleJob(t *testing.T) {
	jobs := []int{42}
	var called bool
	err := OrderedPool(context.Background(), 4, jobs,
		func(j int) workerOutput {
			return workerOutput{index: 0}
		},
		func(out workerOutput) {
			called = true
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("handle was never called")
	}
}

// TestOrderedPoolEmptyJobs verifies that an empty job slice returns
// immediately without error.
func TestOrderedPoolEmptyJobs(t *testing.T) {
	var jobs []int
	err := OrderedPool(context.Background(), 4, jobs,
		func(j int) workerOutput {
			t.Fatal("process should not be called for empty jobs")
			return workerOutput{}
		},
		func(out workerOutput) {
			t.Fatal("handle should not be called for empty jobs")
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestOrderedPoolCancelledContext verifies that a pre-cancelled context
// causes an immediate return with the context error.
func TestOrderedPoolCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	jobs := []int{0, 1, 2, 3, 4}
	err := OrderedPool(ctx, 4, jobs,
		func(j int) workerOutput {
			return workerOutput{index: j}
		},
		func(out workerOutput) {},
	)
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestOrderedPoolCancelMidFlight verifies that cancelling the context
// while workers are processing causes the pool to stop and return
// the context error.
func TestOrderedPoolCancelMidFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var processed atomic.Int32

	jobs := make([]int, 20)
	for i := range jobs {
		jobs[i] = i
	}

	err := OrderedPool(ctx, 2, jobs,
		func(j int) workerOutput {
			n := processed.Add(1)
			if n >= 3 {
				cancel()
			}
			// Simulate some work so cancellation can propagate
			time.Sleep(5 * time.Millisecond)
			return workerOutput{index: j}
		},
		func(out workerOutput) {},
	)

	if err == nil {
		t.Fatal("expected context error, got nil")
	}
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	// Should have processed far fewer than all 20 jobs
	if n := processed.Load(); n >= 20 {
		t.Fatalf("expected early termination, but all %d jobs were processed", n)
	}
}

// TestOrderedPoolMoreWorkersThanJobs ensures correctness when the worker
// count exceeds the job count (extra goroutines should exit cleanly).
func TestOrderedPoolMoreWorkersThanJobs(t *testing.T) {
	jobs := []int{0, 1}
	var got []int
	err := OrderedPool(context.Background(), 10, jobs,
		func(j int) workerOutput {
			return workerOutput{index: j}
		},
		func(out workerOutput) {
			got = append(got, out.index)
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2", len(got))
	}
	for i, v := range got {
		if v != i {
			t.Fatalf("result[%d] = %d, want %d", i, v, i)
		}
	}
}
```

---

## Change 4 (P2): Add comment on `LookupConfig` about shared mutable state

**Why:** `LookupConfig` is passed by value, but its `CacheConfig` field contains a `*sync.Mutex` (pointer) and a `map[string]CacheEntry` (reference type). This means copies of `LookupConfig` share the same mutex and map data. This works correctly now, but it's subtle. If someone later adds a non-pointer mutable field to `CacheConfig`, they'll silently break thread safety. A comment prevents this mistake.

**File:** `pkg/vtclient/vtclient.go`

### Step 4a: Add a comment above `LookupConfig`

Replace the bare struct definition at line 51:

```go
type LookupConfig struct {
```

With:

```go
// LookupConfig is designed to be passed by value. Its CacheConfig field
// contains a *sync.Mutex and a map, both of which are reference types,
// so copies share the same underlying lock and cache data. This is
// intentional — it allows value copies in worker goroutines to safely
// read and write the shared cache. If you add new mutable fields to
// CacheConfig, use pointer types to preserve this property.
type LookupConfig struct {
```

---

## Change 5 (P2): Use local variable for detected algo in `RunHash`

**Why:** Line 139 does `cfg.Algo = detectedAlgo`. Since `cfg` is a value copy (passed by value), this doesn't actually mutate shared state, but it *reads* like a mutation of shared config. Using a local variable makes the intent clearer: "I'm using this algo for this lookup, not changing the config."

**File:** `internal/runner/runner.go`

### Step 5a: Replace `cfg.Algo = detectedAlgo` with a local variable

Change `RunHash` (lines 138-153) from:

```go
func RunHash(arg, detectedAlgo string, cfg vtclient.LookupConfig) int {
	cfg.Algo = detectedAlgo
	hash := strings.ToLower(arg)
	result, err := vtclient.Lookup(hash, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if err := outputpkg.PrintLookupResult(os.Stdout, "", hash, cfg.Output, cfg.Algo, result, nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
```

To:

```go
func RunHash(arg, detectedAlgo string, cfg vtclient.LookupConfig) int {
	algo := detectedAlgo
	cfg.Algo = algo
	hash := strings.ToLower(arg)
	result, err := vtclient.Lookup(hash, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if err := outputpkg.PrintLookupResult(os.Stdout, "", hash, cfg.Output, algo, result, nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
```

**Note:** We still need `cfg.Algo = algo` because `vtclient.Lookup` reads `cfg.Algo` to build the cache key. But the `PrintLookupResult` call now uses the local `algo` variable, making the data flow clearer.

### Step 5b: Same pattern in `processHashToOutput`

Line 194 does `cfg.Algo = job.algo`. This is the same pattern — `cfg` is a value copy. However, this one is already clear because `job.algo` is obviously job-specific. No change needed here; the `job.algo` name makes the intent self-documenting.

---

## Change 6 (P2): Nil-guard `FlushCache` and `Stop` in `run()`

**Why:** `AppConfig.FlushCache` and `AppConfig.Stop` are bare `func()` fields. If either is nil and gets called, Go panics. `main.go` always sets them, but test code constructing `AppConfig` directly (like `TestRunConcurrentInterrupt`) doesn't set them. Adding nil checks in the deferred calls prevents panics if a test or future code path forgets to set them.

**File:** `main.go`

### Step 6a: Add nil guards in `run()`

Change lines 76-77 from:

```go
defer cfg.Stop()
defer cfg.FlushCache()
```

To:

```go
defer func() {
    if cfg.Stop != nil {
        cfg.Stop()
    }
}()
defer func() {
    if cfg.FlushCache != nil {
        cfg.FlushCache()
    }
}()
```

---

## Verification

After all changes, run:

```bash
go build ./...        # must pass — no compile errors
go vet ./...          # must pass — no vet warnings
go test -count=1 ./...  # all tests must pass, including the new runner_test.go
```

Expected output should now include:

```
ok  github.com/nethoundsh/hashchecker/internal/runner  (with test results)
```

instead of the previous:

```
? github.com/nethoundsh/hashchecker/internal/runner [no test files]
```
