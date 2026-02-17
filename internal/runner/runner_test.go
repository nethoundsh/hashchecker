package runner

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOrderedPoolOrdering(t *testing.T) {
	jobs := []int{0, 1, 2, 3, 4, 5}
	var got []int

	err := OrderedPool(context.Background(), 4, jobs,
		func(job int) workerOutput {
			// Intentionally stagger completion so delivery order differs from job order.
			time.Sleep(time.Duration(6-job) * time.Millisecond)
			return workerOutput{index: job}
		},
		func(out workerOutput) {
			got = append(got, out.index)
		},
	)
	if err != nil {
		t.Fatalf("OrderedPool error: %v", err)
	}
	for i := range jobs {
		if got[i] != i {
			t.Fatalf("got order %v, want %v", got, jobs)
		}
	}
}

func TestOrderedPoolSingleWorker(t *testing.T) {
	jobs := []int{0, 1, 2}
	var got []int
	err := OrderedPool(context.Background(), 1, jobs,
		func(job int) workerOutput { return workerOutput{index: job} },
		func(out workerOutput) { got = append(got, out.index) },
	)
	if err != nil {
		t.Fatalf("OrderedPool error: %v", err)
	}
	if len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 2 {
		t.Fatalf("unexpected single-worker output: %v", got)
	}
}

func TestOrderedPoolSingleJob(t *testing.T) {
	jobs := []int{42}
	var got []int
	err := OrderedPool(context.Background(), 8, jobs,
		func(job int) workerOutput { return workerOutput{index: 0, label: "single"} },
		func(out workerOutput) { got = append(got, out.index) },
	)
	if err != nil {
		t.Fatalf("OrderedPool error: %v", err)
	}
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("unexpected single-job output: %v", got)
	}
}

func TestOrderedPoolEmptyJobs(t *testing.T) {
	err := OrderedPool[int](context.Background(), 4, nil,
		func(job int) workerOutput { return workerOutput{index: job} },
		func(out workerOutput) {},
	)
	if err != nil {
		t.Fatalf("OrderedPool with empty jobs should not error: %v", err)
	}
}

func TestOrderedPoolPreCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var processCalls int
	err := OrderedPool(ctx, 4, []int{0, 1, 2},
		func(job int) workerOutput {
			processCalls++
			return workerOutput{index: job}
		},
		func(out workerOutput) {},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if processCalls != 0 {
		t.Fatalf("process should not be called when pre-cancelled, got %d", processCalls)
	}
}

func TestOrderedPoolCancelMidFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make([]int, 50)
	for i := range jobs {
		jobs[i] = i
	}

	var handled atomic.Int32
	var once sync.Once
	err := OrderedPool(ctx, 4, jobs,
		func(job int) workerOutput {
			if job == 0 {
				once.Do(cancel)
			}
			time.Sleep(1 * time.Millisecond)
			return workerOutput{index: job}
		},
		func(out workerOutput) { handled.Add(1) },
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if handled.Load() >= int32(len(jobs)) {
		t.Fatalf("expected cancellation before handling all jobs, handled=%d", handled.Load())
	}
}

func TestOrderedPoolMoreWorkersThanJobs(t *testing.T) {
	jobs := []int{0, 1}
	var got []int
	err := OrderedPool(context.Background(), 16, jobs,
		func(job int) workerOutput { return workerOutput{index: job} },
		func(out workerOutput) { got = append(got, out.index) },
	)
	if err != nil {
		t.Fatalf("OrderedPool error: %v", err)
	}
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("unexpected output: %v", got)
	}
}
