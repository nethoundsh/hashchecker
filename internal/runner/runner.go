package runner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/nethoundsh/hashchecker/pkg/fileinfo"
	filterpkg "github.com/nethoundsh/hashchecker/pkg/filter"
	"github.com/nethoundsh/hashchecker/pkg/hasher"
	outputpkg "github.com/nethoundsh/hashchecker/pkg/output"
	"github.com/nethoundsh/hashchecker/pkg/vtclient"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

type AppConfig struct {
	LookupCfg    vtclient.LookupConfig
	ScanCfg      filterpkg.Config
	Arg          string
	HashListPath string
	Workers      int
	ShowProgress bool
	FlushCache   func()
	Stop         func()
}

type fileResult struct {
	looked    bool
	found     bool
	malicious bool
}

type fileJob struct {
	index int
	path  string
}

type hashJob struct {
	index int
	hash  string
	algo  string
}

type workerOutput struct {
	index  int
	label  string
	output []byte
	result fileResult
	err    error
}

func OrderedPool[J any](
	ctx context.Context,
	workers int,
	jobs []J,
	process func(J) workerOutput,
	handle func(workerOutput),
) error {
	// Cancellation is best-effort: jobs not yet sent or results not yet produced
	// may be dropped once ctx is done.
	if workers <= 1 || len(jobs) <= 1 {
		for _, job := range jobs {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			handle(process(job))
		}
		return nil
	}

	jobCh := make(chan J, workers)
	results := make(chan workerOutput, workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				if ctx.Err() != nil {
					return
				}
				out := process(job)
				select {
				case results <- out:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		pending := make(map[int]workerOutput)
		next := 0
		for out := range results {
			pending[out.index] = out
			for {
				current, ok := pending[next]
				if !ok {
					break
				}
				delete(pending, next)
				handle(current)
				next++
			}
		}
	}()

	interrupted := false
sendJobs:
	for _, job := range jobs {
		select {
		case jobCh <- job:
		case <-ctx.Done():
			interrupted = true
			break sendJobs
		}
	}
	close(jobCh)
	wg.Wait()
	close(results)
	<-done

	if interrupted || ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func RunHash(arg, detectedAlgo string, cfg vtclient.LookupConfig) int {
	cfg.Algo = detectedAlgo
	hash := strings.ToLower(arg)
	result, err := vtclient.Lookup(hash, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if err := outputpkg.PrintLookupResult(os.Stdout, "", hash, cfg.Output, detectedAlgo, result, nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if result.Found && result.Malicious > 0 {
		return 2
	}
	return 0
}

func processFileToOutput(job fileJob, cfg vtclient.LookupConfig) workerOutput {
	path := job.path
	var buf bytes.Buffer
	if cfg.Output == "text" {
		_, _ = fmt.Fprintln(&buf, color.HiBlueString("--- %s ---", path))
	}
	fi, err := os.Stat(path)
	if err != nil {
		return workerOutput{index: job.index, label: path, output: buf.Bytes(), err: err}
	}
	meta := fileinfo.New(path, fi)

	hashes, err := hasher.File(path)
	if err != nil {
		return workerOutput{index: job.index, label: path, output: buf.Bytes(), err: err}
	}
	hash := hashes.ForAlgo(cfg.Algo)

	result, err := vtclient.Lookup(hash, cfg)
	if err != nil {
		return workerOutput{index: job.index, label: path, output: buf.Bytes(), err: err}
	}
	if err := outputpkg.PrintLookupResult(&buf, path, hash, cfg.Output, cfg.Algo, result, &hashes, meta); err != nil {
		return workerOutput{index: job.index, label: path, output: buf.Bytes(), err: err}
	}

	return workerOutput{
		index:  job.index,
		label:  path,
		output: buf.Bytes(),
		result: fileResult{
			looked:    true,
			found:     result.Found,
			malicious: result.Found && result.Malicious > 0,
		},
	}
}

func processHashToOutput(job hashJob, cfg vtclient.LookupConfig) workerOutput {
	var buf bytes.Buffer
	cfg.Algo = job.algo

	result, err := vtclient.Lookup(job.hash, cfg)
	if err != nil {
		return workerOutput{index: job.index, label: job.hash, err: err}
	}
	if err := outputpkg.PrintLookupResult(&buf, "", job.hash, cfg.Output, cfg.Algo, result, nil, nil); err != nil {
		return workerOutput{index: job.index, label: job.hash, output: buf.Bytes(), err: err}
	}

	return workerOutput{
		index:  job.index,
		label:  job.hash,
		output: buf.Bytes(),
		result: fileResult{
			looked:    true,
			found:     result.Found,
			malicious: result.Found && result.Malicious > 0,
		},
	}
}

func handleConcurrentFileResult(out workerOutput, looked, found, malicious *int, bar *mpb.Bar, progress *mpb.Progress) {
	if len(out.output) > 0 {
		if progress != nil {
			_, _ = progress.Write(out.output)
		} else {
			_, _ = os.Stdout.Write(out.output)
		}
	}
	if out.err != nil {
		fmt.Fprintln(os.Stderr, "Error:", out.label, out.err)
	} else {
		if out.result.looked {
			*looked++
		}
		if out.result.found {
			*found++
		}
		if out.result.malicious {
			*malicious++
		}
	}
	if bar != nil {
		bar.Increment()
	}
}

func printTextSummary(looked, found, malicious int, singular, plural string) {
	maliciousStr := color.GreenString("%d", malicious)
	if malicious > 0 {
		maliciousStr = color.RedString("%d", malicious)
	}
	unit := plural
	if looked == 1 {
		unit = singular
	}
	_, _ = fmt.Fprintf(os.Stdout, "Checked %d %s, %d found in VirusTotal, %s malicious\n", looked, unit, found, maliciousStr)
}

func initProgressBar(ctx context.Context, total int64) (*mpb.Progress, *mpb.Bar) {
	p := mpb.NewWithContext(ctx, mpb.WithOutput(os.Stderr))
	b := p.New(total,
		mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding(" ").Rbound("]"),
		mpb.PrependDecorators(decor.Name("Scanning ")),
		mpb.AppendDecorators(
			decor.CountersNoUnit(" %d / %d "),
			decor.AverageETA(decor.ET_STYLE_MMSS),
		),
		mpb.BarRemoveOnComplete(),
	)
	return p, b
}

func RunHashList(path string, cfg vtclient.LookupConfig, workers int) int {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	defer func() { _ = f.Close() }()

	var looked, found, malicious int
	scanner := bufio.NewScanner(f)
	var jobs []hashJob

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ok, detectedAlgo := hasher.IsHexHash(line)
		if !ok {
			fmt.Fprintf(os.Stderr, "Warning: skipping invalid hash: %s\n", line)
			continue
		}
		jobs = append(jobs, hashJob{
			index: len(jobs),
			hash:  strings.ToLower(line),
			algo:  detectedAlgo,
		})
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading hash list:", err)
		return 1
	}

	err = OrderedPool(cfg.VT.Ctx, workers, jobs,
		func(job hashJob) workerOutput {
			return processHashToOutput(job, cfg)
		},
		func(out workerOutput) {
			handleConcurrentFileResult(out, &looked, &found, &malicious, nil, nil)
		},
	)
	if err != nil {
		if cfg.VT.Ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "\nInterrupted")
		} else {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		return 1
	}

	if cfg.Output == "json" {
		if err := outputpkg.PrintJSONSummary(os.Stdout, path, looked, found, malicious); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return 1
		}
	} else {
		printTextSummary(looked, found, malicious, "hash", "hashes")
	}

	if malicious > 0 {
		return 2
	}
	return 0
}

func RunDir(arg string, cfg vtclient.LookupConfig, sc filterpkg.Config, showProgress bool, workers int) int {
	var looked, found, malicious int
	var progress *mpb.Progress
	var bar *mpb.Bar

	files, collectErr := filterpkg.CollectMatchingFiles(arg, sc)
	if collectErr != nil {
		fmt.Fprintln(os.Stderr, "Warning: could not collect files:", collectErr)
	}
	if showProgress && len(files) > 0 {
		progress, bar = initProgressBar(cfg.VT.Ctx, int64(len(files)))
	}

	jobs := make([]fileJob, 0, len(files))
	for i, path := range files {
		jobs = append(jobs, fileJob{index: i, path: path})
	}

	err := OrderedPool(cfg.VT.Ctx, workers, jobs,
		func(job fileJob) workerOutput {
			return processFileToOutput(job, cfg)
		},
		func(out workerOutput) {
			handleConcurrentFileResult(out, &looked, &found, &malicious, bar, progress)
		},
	)

	if progress != nil {
		progress.Wait()
	}

	if err != nil {
		if cfg.VT.Ctx.Err() != nil {
			// On interruption, counters may be partial because in-flight jobs can be dropped.
			fmt.Fprintln(os.Stderr, "\nInterrupted")
		} else {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		return 1
	}

	if cfg.Output == "json" {
		if err := outputpkg.PrintJSONSummary(os.Stdout, arg, looked, found, malicious); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return 1
		}
	} else {
		printTextSummary(looked, found, malicious, "file", "files")
	}

	if malicious > 0 {
		return 2
	}
	return 0
}

// RunFile handles a single explicit file target. Include/exclude glob filters
// are intentionally not applied in this mode.
func RunFile(arg string, fi os.FileInfo, cfg vtclient.LookupConfig, sc filterpkg.Config) int {
	if sc.MinSize > 0 || sc.MaxSize > 0 {
		fileSize := fi.Size()
		if sc.MinSize > 0 && fileSize < sc.MinSize {
			fmt.Fprintf(os.Stderr, "Skipped: %s (%s) is smaller than -min-size %s\n",
				arg, humanize.Bytes(uint64(fileSize)), sc.MinSizeStr)
			return 0
		}
		if sc.MaxSize > 0 && fileSize > sc.MaxSize {
			fmt.Fprintf(os.Stderr, "Skipped: %s (%s) is larger than -max-size %s\n",
				arg, humanize.Bytes(uint64(fileSize)), sc.MaxSizeStr)
			return 0
		}
	}

	hashes, err := hasher.File(arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	hash := hashes.ForAlgo(cfg.Algo)
	result, err := vtclient.Lookup(hash, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if err := outputpkg.PrintLookupResult(os.Stdout, arg, hash, cfg.Output, cfg.Algo, result, &hashes, fileinfo.New(arg, fi)); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if result.Found && result.Malicious > 0 {
		return 2
	}
	return 0
}
