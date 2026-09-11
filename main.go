package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// CIDR represents a parsed CIDR range
type CIDR struct {
	IP   net.IP
	Mask int
}

// Range is an inclusive [Start, End] pair of uint32 IPv4 addresses
type Range struct {
	Start, End uint32
}

// Result holds the probe result for one address
type Result struct {
	IP   string
	Port int
	Open bool // TCP accepted
	RDP  bool // X.224 negotiation succeeded
	NLA  string
	RTT  time.Duration
	Time time.Time
	Err  string
}

const rdpPort = 3389

// x224ConnReq is the 19-byte X.224 Connection Request carrying an
// RDP_NEG_REQ with protocol bits 0x00000000, used to fingerprint RDP.
var x224ConnReq = []byte{
	0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// probeOne performs a TCP connect to ip:port and, on success, the X.224
// RDP negotiation handshake to classify the service (B2).
func probeOne(ctx context.Context, ip string, port int, timeout time.Duration) Result {
	res := Result{IP: ip, Port: port, NLA: "unknown"}
	start := time.Now()
	res.Time = start

	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		res.RTT = time.Since(start)
		if ctx.Err() != nil {
			res.Err = "cancelled"
		}
		return res
	}
	res.Open = true
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(x224ConnReq); err != nil {
		res.Err = "fingerprint failed: " + shortReason(err)
		res.RTT = time.Since(start)
		return res
	}

	buf := make([]byte, 64)
	n, err := io.ReadFull(conn, buf[:19])
	if n > 0 {
		// Best-effort read of the remainder, up to 64 bytes total.
		if m, _ := conn.Read(buf[n:64]); m > 0 {
			n += m
		}
	} else if err != nil {
		res.Err = "fingerprint failed: " + shortReason(err)
		res.RTT = time.Since(start)
		return res
	}
	res.RTT = time.Since(start)

	resp := buf[:n]
	if len(resp) >= 19 && resp[0] == 0x03 && resp[5] == 0xD0 {
		switch resp[12] {
		case 0x02: // RDP_NEG_RSP
			res.RDP = true
			switch proto := binary.LittleEndian.Uint32(resp[15:19]); proto {
			case 0x00000000:
				res.NLA = "not-enforced"
			case 0x00000002:
				res.NLA = "required"
			case 0x00000008:
				res.NLA = "hybrid-ex"
			default:
				res.NLA = "unknown"
			}
			return res
		case 0x03: // RDP_NEG_FAIL
			res.Err = "fingerprint failed: rdp negotiation refused"
			return res
		}
	}
	res.Err = "fingerprint failed: not an rdp response"
	return res
}

// shortReason maps an error to a short, printable reason
func shortReason(err error) string {
	if err == nil {
		return "unknown error"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// ipToUint32 converts an IPv4 address to its uint32 representation
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 |
		uint32(ip4[2])<<8 | uint32(ip4[3])
}

// uint32ToIP converts a uint32 to a dotted-quad IPv4 string
func uint32ToIP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// normalize converts CIDRs to a sorted, disjoint list of inclusive
// ranges, merging overlapping and adjacent ones (B1 stage 1). Memory is
// O(number of CIDRs), not O(number of IPs), and deduplication becomes
// unnecessary because the resulting ranges are disjoint.
func normalize(cidrs []CIDR) []Range {
	type raw struct{ start, end uint32 }
	raws := make([]raw, 0, len(cidrs))
	for _, c := range cidrs {
		hostBits := uint(32 - c.Mask)
		start := ipToUint32(c.IP) & (^uint32(0) << hostBits)
		var end uint32
		if c.Mask == 0 {
			end = ^uint32(0)
		} else {
			end = start + (1 << (32 - c.Mask)) - 1
		}
		raws = append(raws, raw{start, end})
	}
	sort.Slice(raws, func(i, j int) bool { return raws[i].start < raws[j].start })

	merged := make([]Range, 0, len(raws))
	for _, r := range raws {
		if len(merged) > 0 && r.start <= merged[len(merged)-1].End+1 {
			if r.end > merged[len(merged)-1].End {
				merged[len(merged)-1].End = r.end
			}
		} else {
			merged = append(merged, Range{Start: r.start, End: r.end})
		}
	}
	return merged
}

// totalIPs returns the number of unique addresses covered by the ranges
func totalIPs(ranges []Range) uint64 {
	var total uint64
	for _, r := range ranges {
		total += uint64(r.End - r.Start) + 1
	}
	return total
}

// rawAddressCount is the pre-merge address count, for diagnostics only
func rawAddressCount(cidrs []CIDR) uint64 {
	var total uint64
	for _, c := range cidrs {
		total += uint64(1) << uint(32-c.Mask)
	}
	return total
}

// resultWriter streams one formatted record per host as results arrive
type resultWriter interface {
	Write(res Result) error
	Close() error
}

// outputFormat selects the structured output format (B3)
type outputFormat string

const (
	formatTXT     outputFormat = "txt"
	formatJSONL   outputFormat = "jsonl"
	formatCSV     outputFormat = "csv"
	formatTargets outputFormat = "targets"
)

func parseFormat(s string) (outputFormat, bool) {
	switch outputFormat(s) {
	case formatTXT, formatJSONL, formatCSV, formatTargets:
		return outputFormat(s), true
	}
	return "", false
}

type bufferedWriter struct{ w *bufio.Writer }

func (b *bufferedWriter) flush() error { return b.w.Flush() }
func (b *bufferedWriter) Close() error { return b.w.Flush() }

type txtWriter struct{ *bufferedWriter }

func (t *txtWriter) Write(r Result) error {
	if _, err := fmt.Fprintln(t.w, r.IP); err != nil {
		return err
	}
	return t.flush()
}

type targetsWriter struct{ *bufferedWriter }

func (t *targetsWriter) Write(r Result) error {
	if _, err := fmt.Fprintf(t.w, "%s:%d\n", r.IP, r.Port); err != nil {
		return err
	}
	return t.flush()
}

type jsonlWriter struct{ *bufferedWriter }

type jsonlRecord struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	RDP  bool   `json:"rdp"`
	NLA  string `json:"nla"`
	RTT  int64  `json:"rtt_ms"`
	T    string `json:"t"`
	Err  string `json:"err,omitempty"`
}

func (j *jsonlWriter) Write(r Result) error {
	rec := jsonlRecord{
		IP:   r.IP,
		Port: r.Port,
		RDP:  r.RDP,
		NLA:  r.NLA,
		RTT:  int64(r.RTT / time.Millisecond),
		T:    r.Time.UTC().Format(time.RFC3339),
		Err:  r.Err,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := j.w.Write(append(data, '\n')); err != nil {
		return err
	}
	return j.flush()
}

type csvWriter struct {
	*bufferedWriter
	cw *csv.Writer
}

func (c *csvWriter) Write(r Result) error {
	err := c.cw.Write([]string{
		r.IP,
		strconv.Itoa(r.Port),
		strconv.FormatBool(r.RDP),
		r.NLA,
		strconv.FormatInt(int64(r.RTT/time.Millisecond), 10),
		r.Time.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	c.cw.Flush()
	if err := c.cw.Error(); err != nil {
		return err
	}
	return c.flush()
}

// newResultWriter builds the writer for the selected format. CSV gets a
// header row; all writers flush per record so results stream out as they
// are discovered.
func newResultWriter(f outputFormat, out io.Writer) (resultWriter, error) {
	buf := bufio.NewWriter(out)
	switch f {
	case formatTXT:
		return &txtWriter{&bufferedWriter{buf}}, nil
	case formatTargets:
		return &targetsWriter{&bufferedWriter{buf}}, nil
	case formatJSONL:
		return &jsonlWriter{&bufferedWriter{buf}}, nil
	case formatCSV:
		cw := csv.NewWriter(buf)
		if err := cw.Write([]string{"ip", "port", "rdp", "nla", "rtt_ms", "t"}); err != nil {
			return nil, err
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			return nil, err
		}
		return &csvWriter{&bufferedWriter{buf}, cw}, nil
	}
	return nil, fmt.Errorf("unknown output format: %s", f)
}

// runPipeline is the streaming scan (B1 stages 2 and 3): a fixed pool of
// `workers` goroutines reads addresses from a shared jobs channel, probes
// each one, and hands results to a single reporter goroutine that updates
// counters and calls emit. No full-RAM materialization of the IP space:
// memory is bounded by the range count plus the channel buffers.
func runPipeline(ctx context.Context, ranges []Range, workers int, timeout time.Duration, emit func(Result)) error {
	total := int64(totalIPs(ranges))

	jobCh := make(chan uint32, workers*2)
	resCh := make(chan Result, workers*2)

	var processed, open atomic.Int64

	// Stage 3: single reporter goroutine
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

	// Progress reporter: the only goroutine that prints progress.
	// Non-TTY: one line per 5000 completions (B5/Tty handling lands in
	// the follow-up fix commit).
	var progWg sync.WaitGroup
	progWg.Add(1)
	progDone := make(chan struct{})
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
				if n-last >= 5000 || (n == total && n != 0) {
					last = n
					fmt.Printf("[*] Progress: %d/%d (%.1f%%)\n", n, total, float64(n)/float64(total)*100)
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
				res := probeOne(ctx, uint32ToIP(a), rdpPort, timeout)
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
	return nil
}

func main() {
	// Parse CLI args
	inputFile := ""
	outputFile := "" // empty = stdout
	concurrency := 100
	timeout := 2 * time.Second
	maxCIDR := 0 // 0 = no limit, skip CIDRs with prefix smaller than this
	formatStr := "txt"
	onlyNLAOpen := false

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o", "--output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "-c", "--concurrency":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					concurrency = n
				}
				i++
			}
		case "-t", "--timeout":
			if i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil {
					timeout = d
				}
				i++
			}
		case "--max-cidr":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n >= 0 && n <= 32 {
					maxCIDR = n
				}
				i++
			}
		case "--format":
			if i+1 < len(args) {
				formatStr = args[i+1]
				i++
			}
		case "--only-nla-open":
			onlyNLAOpen = true
		case "-h", "--help":
			printUsage()
			return
		default:
			if !strings.HasPrefix(args[i], "-") && inputFile == "" {
				inputFile = args[i]
			}
		}
	}

	if inputFile == "" {
		printUsage()
		os.Exit(1)
	}

	f, ok := parseFormat(formatStr)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown format: %s (valid: txt, jsonl, csv, targets)\n", formatStr)
		os.Exit(2)
	}

	// Handle SIGINT/SIGTERM: first signal stops new probes (results
	// already emitted are in the output), second exits immediately.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

	// Read and parse CIDRs
	fmt.Println("[*] Loading CIDRs...")
	cidrs, err := readCIDRs(inputFile, maxCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Parsed %d CIDR ranges (after filtering)\n", len(cidrs))

	// Normalize to disjoint ranges (dedup by construction)
	ranges := normalize(cidrs)
	total := totalIPs(ranges)
	fmt.Printf("[*] %d CIDR ranges -> %d unique addresses (raw addresses before merge: %d)\n",
		len(cidrs), total, rawAddressCount(cidrs))

	// Output destination: file when -o is set, stdout otherwise. The
	// file is created up front so downstream scripts always find it,
	// even when empty.
	out := io.Writer(os.Stdout)
	var outFile *os.File
	if outputFile != "" {
		outFile, err = os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
		out = outFile
	}

	if total == 0 {
		if outputFile != "" {
			fmt.Printf("[!] No live hosts; empty report written to: %s\n", outputFile)
		} else {
			fmt.Println("[!] No valid IPs to scan")
		}
		os.Exit(0)
	}

	rw, err := newResultWriter(f, out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Scanning TCP/3389 (concurrency: %d, timeout: %s, format: %s)...\n",
		concurrency, timeout, f)

	// The reporter goroutine calls emit sequentially, so no locking is
	// needed around rw.
	var openCount, written atomic.Int64
	var writeFailed atomic.Bool
	emit := func(r Result) {
		if r.Open {
			openCount.Add(1)
		}
		if !r.Open {
			return
		}
		if onlyNLAOpen && r.NLA != "not-enforced" {
			return
		}
		if err := rw.Write(r); err != nil {
			if !writeFailed.Swap(true) {
				fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
			}
			return
		}
		written.Add(1)
	}

	if err := runPipeline(ctx, ranges, concurrency, timeout, emit); err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
	}
	rw.Close()

	if interrupted.Load() {
		fmt.Fprintf(os.Stderr, "[+] %d result(s) written before interrupt\n", written.Load())
		os.Exit(130)
	}

	fmt.Printf("[+] Scan complete\n")
	fmt.Printf("[+] %d live host(s) found; %d written to output\n", openCount.Load(), written.Load())
	if outputFile != "" {
		if written.Load() == 0 {
			fmt.Printf("[!] No live hosts; empty report written to: %s\n", outputFile)
		} else {
			fmt.Printf("[+] Results saved to: %s\n", outputFile)
		}
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `rdp-scan - Lightweight RDP exposure scanner

Usage: rdp-scan <input> [options]

Arguments:
  <input>           Path to file containing CIDR ranges

Options:
  -o, --output      Output file for results (default: stdout)
  -c, --concurrency Number of concurrent probes (default: 100)
  -t, --timeout     Probe timeout (default: 2s, e.g., 500ms, 2s)
  --max-cidr        Skip CIDRs whose prefix is smaller than N.
                    Example: --max-cidr 24 scans only /24 and smaller.
  --format          Output format: txt, jsonl, csv, targets (default: txt)
  --only-nla-open   Only report hosts with NLA not enforced
  -h, --help        Show this help message

Input file format:
  One CIDR per line, e.g.:
    1.0.1.0/24
    1.0.2.0/23
    
  Lines starting with # are comments.
  Blank lines are ignored.
  Malformed entries are skipped with a warning.

Examples:
  rdp-scan ranges.txt
  rdp-scan ranges.txt -o results.txt -c 200
  rdp-scan ranges.txt --format targets -o live.txt
  rdp-scan ranges.txt --format targets --only-nla-open -o live.txt
  rdp-scan ranges.txt -c 50 -t 1s
  rdp-scan ranges.txt --max-cidr 24
`)
}

func readCIDRs(filename string, maxCIDR int) ([]CIDR, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cidrs []CIDR
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and blank lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if cidr, ok := parseCIDR(line); ok {
			// Skip CIDRs with prefix strictly smaller than maxCIDR
			if maxCIDR > 0 && cidr.Mask < maxCIDR {
				totalIPs := uint64(1) << uint(32-cidr.Mask)
				fmt.Fprintf(os.Stderr, "[!] Skipping %s/%d (%d IPs) - use --max-cidr to change threshold\n",
					cidr.IP.String(), cidr.Mask, totalIPs)
				continue
			}
			cidrs = append(cidrs, cidr)
		} else {
			fmt.Fprintf(os.Stderr, "[!] Skipping malformed CIDR: %s\n", line)
		}
	}
	return cidrs, scanner.Err()
}

func parseCIDR(s string) (CIDR, bool) {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return CIDR{}, false
	}
	ip := net.ParseIP(parts[0])
	if ip == nil {
		return CIDR{}, false
	}
	mask, err := strconv.Atoi(parts[1])
	if err != nil || mask < 0 || mask > 32 {
		return CIDR{}, false
	}
	// Only support IPv4
	if ip.To4() == nil {
		return CIDR{}, false
	}
	return CIDR{IP: ip.To4(), Mask: mask}, true
}
