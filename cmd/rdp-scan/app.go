package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"rdp-scan/internal/cidr"
	"rdp-scan/internal/probe"
	"rdp-scan/internal/report"
	"rdp-scan/internal/scan"
)

// stats collects scan counters from the emit closure (called
// sequentially by the single reporter goroutine).
type stats struct {
	open        atomic.Int64
	written     atomic.Int64
	writeFailed atomic.Bool
}

// installSignalHandler wires SIGINT/SIGTERM: the first signal stops new
// probes (results already emitted stay in the output), the second exits
// immediately with 130. It returns the interrupted flag and a cleanup
// function.
func installSignalHandler(cancel context.CancelFunc) (*atomic.Bool, func()) {
	var interrupted atomic.Bool
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range sigCh {
			if interrupted.CompareAndSwap(false, true) {
				fmt.Fprintln(os.Stderr, "[!] Interrupted — writing partial results")
				cancel()
			} else {
				os.Exit(130)
			}
		}
	}()
	return &interrupted, func() { signal.Stop(sigCh) }
}

// run executes the scan and returns the process exit code: 0 success,
// 1 runtime failure (input read, output write), 2 usage error,
// 130 interrupted.
func run(args []string) int {
	cfg, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		printUsage()
		return 2
	}
	if cfg.help {
		printUsage()
		return 0
	}
	if cfg.input == "" {
		printUsage()
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interrupted, stopSignals := installSignalHandler(cancel)
	defer stopSignals()

	// All status output goes to stderr; results are the only stdout
	// writes.
	fmt.Fprintln(os.Stderr, "[*] Loading CIDRs...")
	cidrs, err := cidr.ReadCIDRs(cfg.input, cfg.maxCIDR, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[*] Parsed %d CIDR ranges (after filtering)\n", len(cidrs))

	// Normalize to disjoint ranges (dedup by construction)
	ranges := cidr.Normalize(cidrs)
	total := cidr.TotalIPs(ranges)
	fmt.Fprintf(os.Stderr, "[*] %d CIDR ranges -> %d unique addresses (raw addresses before merge: %d)\n",
		len(cidrs), total, cidr.RawAddressCount(cidrs))

	// Output destination: file when -o is set, stdout otherwise. The
	// file is created up front so downstream scripts always find it,
	// even when empty.
	out := io.Writer(os.Stdout)
	if cfg.output != "" {
		file, cerr := os.Create(cfg.output)
		if cerr != nil {
			fmt.Fprintf(os.Stderr, "error creating output file: %v\n", cerr)
			return 1
		}
		defer file.Close()
		out = file
	}

	if total == 0 {
		if cfg.output != "" {
			fmt.Fprintf(os.Stderr, "[!] No live hosts; empty report written to: %s\n", cfg.output)
		} else {
			fmt.Fprintln(os.Stderr, "[!] No valid IPs to scan")
		}
		return 0
	}

	rw, err := report.New(cfg.format, out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[*] Scanning TCP/3389 (concurrency: %d, timeout: %s, format: %s)...\n",
		cfg.concurrency, cfg.timeout, cfg.format)

	st := &stats{}
	emit := func(r probe.Result) {
		if r.Open {
			st.open.Add(1)
		}
		if !r.Open {
			return
		}
		if cfg.onlyNLAOpen && r.NLA != "not-enforced" {
			return
		}
		if werr := rw.Write(r); werr != nil {
			if !st.writeFailed.Swap(true) {
				fmt.Fprintf(os.Stderr, "error writing output: %v\n", werr)
			}
			return
		}
		st.written.Add(1)
	}

	if perr := scan.RunPipeline(ctx, ranges, cfg.concurrency, cfg.timeout, emit); perr != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", perr)
	}
	rw.Close()

	if interrupted.Load() {
		fmt.Fprintf(os.Stderr, "[+] %d result(s) written before interrupt\n", st.written.Load())
		return 130
	}
	if st.writeFailed.Load() {
		return 1
	}

	fmt.Fprintln(os.Stderr, "[+] Scan complete")
	fmt.Fprintf(os.Stderr, "[+] %d live host(s) found; %d written to output\n",
		st.open.Load(), st.written.Load())
	if cfg.output != "" {
		if st.written.Load() == 0 {
			fmt.Fprintf(os.Stderr, "[!] No live hosts; empty report written to: %s\n", cfg.output)
		} else {
			fmt.Fprintf(os.Stderr, "[+] Results saved to: %s\n", cfg.output)
		}
	}
	return 0
}
