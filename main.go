package main

import (
	"bufio"
	"context"
	"fmt"
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

// ScanResult holds the result of a scan
type ScanResult struct {
	IP   string
	Open bool
}

func main() {
	// Parse CLI args
	inputFile := ""
	outputFile := "rdp_live.txt"
	concurrency := 100
	timeout := 2 * time.Second
	maxCIDR := 0 // 0 = no limit, skip CIDRs with prefix smaller than this (e.g., 20 skips /19, /16, ...)

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

	// A6: handle SIGINT/SIGTERM so partial results are saved instead of lost.
	// First signal: stop new probes, save what was found, exit 130.
	// Second signal: exit immediately with 130.
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

	// Expand to unique IPs with progress
	fmt.Println("[*] Expanding ranges...")
	ips := expandCIDRs(cidrs)
	fmt.Printf("[+] %d unique IPs\n", len(ips))

	if len(ips) == 0 {
		fmt.Println("[!] No valid IPs to scan")
		os.Exit(0)
	}

	// A5: numeric sort (uint32 compare) for deterministic, human-sensible order
	sort.Slice(ips, func(i, j int) bool { return ips[i] < ips[j] })

	// Scan
	fmt.Printf("[*] Scanning TCP/3389 (concurrency: %d, timeout: %s)...\n", concurrency, timeout)
	results := scanIPs(ctx, ips, concurrency, timeout)

	// Filter open hosts
	var openIPs []string
	for _, r := range results {
		if r.Open {
			openIPs = append(openIPs, r.IP)
			fmt.Printf("[+] %s:3389 OPEN\n", r.IP)
		}
	}

	if interrupted.Load() {
		// A6: persist the hosts discovered so far, then exit 130
		if err := saveResults(openIPs, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "error saving results: %v\n", err)
		} else {
			fmt.Printf("[+] %d partial result(s) saved to: %s\n", len(openIPs), outputFile)
		}
		os.Exit(130)
	}

	fmt.Printf("[+] Scan complete\n")
	fmt.Printf("[+] %d RDP host(s) found\n", len(openIPs))

	// Save results
	if len(openIPs) > 0 {
		if err := saveResults(openIPs, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving results: %v\n", err)
		} else {
			fmt.Printf("[+] Results saved to: %s\n", outputFile)
		}
	} else {
		fmt.Println("[!] No open RDP hosts found")
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `rdp-scan - Lightweight RDP exposure scanner

Usage: rdp-scan <input> [options]

Arguments:
  <input>           Path to file containing CIDR ranges

Options:
  -o, --output      Output file for found hosts (default: rdp_live.txt)
  -c, --concurrency Number of concurrent TCP checks (default: 100)
  -t, --timeout     TCP connection timeout (default: 2s, e.g., 500ms, 2s)
  --max-cidr        Skip CIDRs whose prefix is smaller than N.
                    Example: --max-cidr 24 scans only /24 and smaller.
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
			// Skip large CIDRs if maxCIDR is set (prefix strictly smaller than the threshold)
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

// ipToUint32 converts an IPv4 address to its uint32 representation
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 |
		uint32(ip4[2])<<8 | uint32(ip4[3])
}

// uint32ToIP converts a uint32 to dotted-quad IPv4 string
func uint32ToIP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// expandCIDRs expands CIDR ranges to unique IPs as uint32 values.
// A3: progress fires inside the inner loop, every 100k iterations of the
// current CIDR, so a single large CIDR reports progress while expanding.
func expandCIDRs(cidrs []CIDR) []uint32 {
	ipSet := make(map[uint32]struct{})

	totalIPs := uint64(0)
	reportEvery := uint64(100_000)
	for _, cidr := range cidrs {
		hostBits := uint(32 - cidr.Mask)
		count := uint64(1) << hostBits
		// Normalize to the network address (clear host bits)
		mask := ^uint32(0) << hostBits
		start := ipToUint32(cidr.IP) & mask

		for i := uint64(0); i < count; i++ {
			ipSet[start+uint32(i)] = struct{}{}
			if (i+1)%reportEvery == 0 {
				fmt.Fprintf(os.Stderr,
					"[*] Expanding: %d/%d in current CIDR, %d unique total\n",
					i+1, count, len(ipSet))
			}
		}
		totalIPs += count
	}

	ips := make([]uint32, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	fmt.Fprintf(os.Stderr, "[*] Expanded %d total IPs from %d CIDRs\n", totalIPs, len(cidrs))
	return ips
}

// scanIPs probes TCP/3389 for every IP using a fixed worker pool of
// `concurrency` goroutines reading from a shared jobs channel. No
// goroutine-per-IP: memory stays O(concurrency) regardless of range size.
func scanIPs(ctx context.Context, ips []uint32, concurrency int, timeout time.Duration) []ScanResult {
	results := make([]ScanResult, len(ips))
	jobs := make(chan int, concurrency*2)
	var wg sync.WaitGroup
	var processed atomic.Int64
	total := int64(len(ips))

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				n := ips[idx]
				ipStr := uint32ToIP(n)
				result := ScanResult{IP: ipStr}
				if ctx.Err() == nil {
					addr := net.JoinHostPort(ipStr, "3389")
					conn, err := net.DialTimeout("tcp", addr, timeout)
					if err == nil {
						conn.Close()
						result.Open = true
					}
				}
				// Each index is written by exactly one worker: no lock needed
				results[idx] = result

				processed.Add(1)
				// Print progress every 500 or at completion
				if processed.Load()%500 == 0 || processed.Load() == total {
					fmt.Printf("[*] Progress: %d/%d (%.1f%%)\n",
						processed.Load(), total, float64(processed.Load())/float64(total)*100)
				}
			}
		}()
	}

	go func() {
		for i := range ips {
			jobs <- i
		}
		close(jobs)
	}()

	wg.Wait()
	return results
}

func saveResults(ips []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, ip := range ips {
		fmt.Fprintln(writer, ip)
	}
	return writer.Flush()
}
