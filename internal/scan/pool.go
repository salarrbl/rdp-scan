// Package scan runs the streaming scan pipeline: a fixed worker pool
// over a shared jobs channel, a single reporter goroutine, and the
// progress renderer.
package scan

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"rdp-scan/internal/cidr"
	"rdp-scan/internal/probe"
)

// probeFunc probes one address; it is the test seam for probe.Probe.
type probeFunc func(ctx context.Context, ip string, port int, timeout time.Duration) probe.Result

// RunPipeline is the streaming scan (B1 stages 2 and 3): a fixed pool of
// `workers` goroutines reads addresses from a shared jobs channel, probes
// each one with the RDP fingerprint, and hands results to a single
// reporter goroutine that updates counters and calls emit for every
// result. No full-RAM materialization of the IP space: memory is bounded
// by the range count plus the channel buffers, so a /8 scans with the
// same footprint as a /24.
func RunPipeline(ctx context.Context, ranges []cidr.Range, workers int, timeout time.Duration, emit func(probe.Result)) error {
	return run(ctx, ranges, workers, timeout, probe.Probe, emit)
}

func run(ctx context.Context, ranges []cidr.Range, workers int, timeout time.Duration, probeFn probeFunc, emit func(probe.Result)) error {
	total := int64(cidr.TotalIPs(ranges))
	start := time.Now()

	jobCh := make(chan uint32, workers*2)
	resCh := make(chan probe.Result, workers*2)

	var processed, open atomic.Int64

	// Stage 3: single reporter goroutine. It is the only writer of the
	// counters, so each Add returns a consistent snapshot (C1).
	var repWg sync.WaitGroup
	repWg.Add(1)
	go func() {
		defer repWg.Done()
		for r := range resCh {
			emit(r)
			if r.Open {
				open.Add(1)
			}
			processed.Add(1)
		}
	}()

	// Progress reporter: the only goroutine that prints progress (C2).
	// TTY: overwrite the line every 250ms; not on TTY: one line per
	// 5000 completions.
	tty := isTerminal(os.Stderr)
	progDone := make(chan struct{})
	var progWg sync.WaitGroup
	progWg.Add(1)
	go func() {
		defer progWg.Done()
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		last := int64(0)
		for {
			select {
			case <-progDone:
				return
			case <-tick.C:
				n := processed.Load()
				if tty {
					if n != last {
						last = n
						renderProgress(n, total, open.Load(), time.Since(start))
					}
				} else if n-last >= 5000 {
					last = n
					renderProgress(n, total, open.Load(), time.Since(start))
					fmt.Fprintln(os.Stderr)
				}
			}
		}
	}()

	// Stage 2: fixed worker pool, one goroutine per worker, no
	// per-IP goroutines
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobCh {
				res := probeFn(ctx, cidr.Uint32ToIP(a), probe.Port, timeout)
				resCh <- res
			}
		}()
	}

	// Single producer enumerates all addresses from the normalized
	// ranges (uint32 arithmetic only), then closes the channel
	go func() {
		for _, r := range ranges {
			for a := r.Start; ; a++ {
				jobCh <- a
				if a == r.End {
					break
				}
			}
		}
		close(jobCh)
	}()

	wg.Wait()
	close(resCh)
	repWg.Wait()
	close(progDone)
	progWg.Wait()

	// Final progress render: 100%, then clear the line on TTY before
	// the caller prints the summary.
	renderProgress(total, total, open.Load(), time.Since(start))
	if tty {
		fmt.Fprint(os.Stderr, "\r\033[K\n")
	} else {
		fmt.Fprintln(os.Stderr)
	}
	return nil
}
