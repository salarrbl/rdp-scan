package main

import (
	"bufio"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CIDR represents a parsed CIDR range
type CIDR struct {
	IP   net.IP
	Mask int
}

// ScanResult holds the result of a scan
type ScanResult struct {
	IP      string
	Open    bool
	Status  string // OPEN, CLOSED, TIMEOUT
	Duration time.Duration
}

// Job represents a scan job for a worker
type Job struct {
	IP     string
	Result chan ScanResult
}

// Config holds configuration
type Config struct {
	InputFile    string
	OutputFile   string
	Workers      int
	MaxCIDR      int
	ShowProgress bool
}

func main() {
	// Load config from flags
	config := loadConfig()

	if config.InputFile == "" {
		printUsage()
		os.Exit(1)
	}

	// Read and parse CIDRs
	fmt.Println("[*] Loading CIDRs...")
	cidrs, err := readCIDRs(config.InputFile, config.MaxCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Parsed %d CIDR ranges (after filtering)\n", len(cidrs))

	// Expand to unique IPs with progress
	fmt.Println("[*] Expanding ranges...")
	ips, err := expandCIDRs(cidrs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error expanding CIDRs: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] %d unique IPs\n", len(ips))

	if len(ips) == 0 {
		fmt.Println("[!] No valid IPs to scan")
		os.Exit(0)
	}

	// Sort IPs for consistent output
	sort.Strings(ips)

	// Scan with worker pool
	fmt.Printf("[*] Scanning TCP/3389 (workers: %d)...\n", config.Workers)
	
	results := scanIPs(ips, config)

	// Filter open and print
	var openIPs []ScanResult
	openCount := 0
	for _, r := range results {
		if r.Open {
			openIPs = append(openIPs, r)
			fmt.Printf("[+] %s:3389 OPEN (%s)\n", r.IP, r.Status)
		}
	}

	fmt.Printf("[+] Scan complete\n")
	fmt.Printf("[+] %d RDP host(s) found\n", openCount)

	// Save results
	if openCount > 0 {
		if err := saveResults(openIPs, config.OutputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving results: %v\n", err)
		} else {
			fmt.Printf("[+] Results saved to: %s\n", config.OutputFile)
		}
	} else {
		fmt.Println("[!] No open RDP hosts found")
	}
}

func loadConfig() *Config {
	inputFile := ""
	outputFile := "rdp_live.txt"
	workers := 50
	maxCIDR := 0
	showProgress := true

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o", "--output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "-w", "--workers":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					workers = n
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
		case "--no-progress":
			showProgress = false
		case "-h", "--help":
			printUsage()
			os.Exit(0)
		default:
			if !strings.HasPrefix(args[i], "-") && inputFile == "" {
				inputFile = args[i]
			}
		}
	}

	return &Config{
		InputFile:    inputFile,
		OutputFile:   outputFile,
		Workers:      workers,
		MaxCIDR:      maxCIDR,
		ShowProgress: showProgress,
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `rdp-scan - Fast RDP exposure scanner with worker pool

Usage: rdp-scan <input> [options]

Arguments:
  <input>           Path to file containing CIDR ranges

Options:
  -o, --output      Output file for found hosts (default: rdp_live.txt)
  -w, --workers     Worker pool size (default: 50)
  --max-cidr        Skip CIDRs smaller than this prefix (e.g., 20 skips /20 and larger networks)
  --no-progress     Disable progress display
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
  rdp-scan ranges.txt -w 100 -c 200
  rdp-scan ranges.txt -w 50 --no-progress
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
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if cidr, ok := parseCIDR(line); ok {
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
	if ip.To4() == nil {
		return CIDR{}, false
	}
	return CIDR{IP: ip.To4(), Mask: mask}, true
}

func expandCIDRs(cidrs []CIDR) ([]string, error) {
	ipSet := make(map[string]struct{})
	var mu sync.Mutex
	totalIPs := 0
	var totalCounter int64

	for _, cidr := range cidrs {
		start := ipToBigInt(cidr.IP)
		hostBits := 32 - cidr.Mask
		count := uint64(1) << uint(hostBits)

		current := new(big.Int).Set(start)
		one := big.NewInt(1)

		for i := uint64(0); i < count; i++ {
			ipStr := bigIntToIP(current)
			
			mu.Lock()
			ipSet[ipStr] = struct{}{}
			mu.Unlock()
			
			current.Add(current, one)
		}
		totalIPs += int(count)

		atomic.AddInt64(&totalCounter, int64(count))
		if atomic.LoadInt64(&totalCounter)%50000 == 0 {
			ipsRead := atomic.LoadInt64(&totalCounter)
			fmt.Fprintf(os.Stderr, "[*] Expanding... %d unique IPs so far\n", ipsRead)
		}
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	fmt.Fprintf(os.Stderr, "[*] Expanded %d total IPs from %d CIDRs\n", totalIPs, len(cidrs))
	return ips, nil
}

func ipToBigInt(ip net.IP) *big.Int {
	ip = ip.To4()
	if ip == nil {
		return big.NewInt(0)
	}
	return big.NewInt(0).SetBytes(ip)
}

func bigIntToIP(n *big.Int) string {
	bytes := n.Bytes()
	if len(bytes) < 4 {
		padded := make([]byte, 4)
		copy(padded[4-len(bytes):], bytes)
		bytes = padded
	}
	return fmt.Sprintf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3])
}

func scanIPs(ips []string, config *Config) []ScanResult {
	var wg sync.WaitGroup
	results := make([]ScanResult, len(ips))
	var processed atomic.Int64
	total := int64(len(ips))

	// Worker pool - buffered channels
	jobChan := make(chan Job, 1000)
	resultsChan := make(chan ResultItem, 2000)
	var resultsMu sync.Mutex
	finishedCount := int64(0)
	totalWorkers := int32(config.Workers)

	// Start workers
	var workersWg sync.WaitGroup
	for id := 0; id < config.Workers; id++ {
		workersWg.Add(1)
		go worker(id, jobChan, resultsChan, &resultsMu, &finishedCount, &totalWorkers)
	}

	// Start result aggregator
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Queue jobs
	go func() {
		for _, ip := range ips {
			jobChan <- Job{
				IP:     ip,
				Result: make(chan ScanResult),
			}
			processed.Add(1)
			if int(processed.Load())%1000 == 0 {
				fmt.Printf("[*] Progress: %d/%d (%.1f%%)\r", 
					processed.Load(), total, 
					float64(processed.Load())/float64(total)*100)
			}
		}
		close(jobChan)
	}()

	// Collect results
	for result := range resultsChan {
		results[result.Index] = result.ScanResult
	}

	workersWg.Wait()
	fmt.Println()

	return results
}

type ResultItem struct {
	ScanResult  ScanResult
	Index       int
}

func worker(id int, jobs <-chan Job, results chan<- ResultItem, resultsMu *sync.Mutex, finishedCount *int64, totalWorkers *int32) {
	defer atomic.AddInt32(totalWorkers, -1)
	defer workersWg.Done()

	for job := range jobs {
		result := ScanResult{
			IP:      job.IP,
			Duration: 0,
		}

		addr := net.JoinHostPort(job.IP, "3389")
		start := time.Now()
		
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			defer conn.Close()
			
			conn.SetReadDeadline(time.Now().Add(time.Second))
			
			buf := make([]byte, 512)
			n, err := conn.Read(buf)
			if err == nil && n > 0 {
				result.Open = true
				result.Status = "OPEN"
			} else if err == os.ErrDeadlineExceeded {
				result.Open = false
				result.Status = "TIMEOUT"
			} else if n == 0 {
				result.Open = true
				result.Status = "OPEN"
			} else {
				result.Open = false
				result.Status = "CLOSED"
			}
		} else {
			result.Open = false
			result.Status = "TIMEOUT"
		}

		result.Duration = time.Since(start)
		
		resultsMu.Lock()
		results <- ResultItem{
			ScanResult: result,
			Index:      len(results),
		}
		atomic.AddInt64(finishedCount, 1)
		resultsMu.Unlock()
	}
}

var workersWg sync.WaitGroup

func saveResults(results []ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, r := range results {
		if r.Open {
			fmt.Fprintf(writer, "%s:3389 %s %.3fs\n", r.IP, r.Status, r.Duration.Seconds())
		}
	}
	return writer.Flush()
}
