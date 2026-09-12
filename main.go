package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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

// rdpPort is the TCP port this scanner probes.
const rdpPort = "3389"

// TPKT (RFC 1006) / X.224 (ISO 8073) framing used by RDP (MS-RDPBCGR 2.2).
const (
	tpktVersion   = 3
	tpktHeaderLen = 4

	// x224CodeCC is the Connection Confirm TPDU code. The low nibble of an
	// X.224 TPDU code carries the "credit" field, so comparisons mask it off.
	x224CodeCC = 0xD0

	// minTPKTLen is the smallest plausible TPKT packet: 4 byte header plus the
	// X.224 length indicator and TPDU code. maxTPKTLen caps how much of a
	// response we buffer - a real Connection Confirm is ~19 bytes.
	minTPKTLen = tpktHeaderLen + 2
	maxTPKTLen = 4096

	// minX224LI is the shortest X.224 CC header after the length indicator:
	// code(1) + DST-REF(2) + SRC-REF(2) + class(1).
	minX224LI = 6
)

// expandProgressEvery is how many IPs may be expanded between progress lines.
const expandProgressEvery int64 = 50000

// errIPv6Unsupported marks input that is a perfectly valid IPv6 CIDR but out of
// scope for this IPv4-only scanner. Keeping it distinct from a parse failure is
// what lets readCIDRs report "IPv6 not supported" instead of "malformed".
var errIPv6Unsupported = errors.New("IPv6 is not supported (this scanner is IPv4-only)")

// CIDR represents a parsed CIDR range
type CIDR struct {
	IP   net.IP
	Mask int
}

// ScanResult holds the result of a scan.
//
// Open means "3389/tcp spoke RDP": the host answered our X.224 Connection
// Request with an X.224 Connection Confirm. TCPOpen records that the TCP
// connection itself succeeded, which is what separates "port closed/filtered"
// from "port open, but something other than RDP is behind it".
type ScanResult struct {
	IP      string
	Open    bool
	TCPOpen bool
	Detail  string
}

func main() {
	// Parse CLI args
	inputFile := ""
	outputFile := "rdp_live.txt"
	concurrency := 100
	timeout := 5 * time.Second
	maxCIDR := 0 // 0 = no limit, skip CIDRs smaller than this (e.g., 20 skips /20 and larger networks)

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

	// Scan
	fmt.Printf("[*] Scanning TCP/3389 (concurrency: %d, timeout: %s)...\n", concurrency, timeout)
	results := scanIPs(ips, concurrency, timeout)

	// Filter and report
	var openIPs, nonRDPIP []string
	for _, r := range results {
		switch {
		case r.Open:
			openIPs = append(openIPs, r.IP)
			fmt.Printf("[+] %s:%s OPEN\n", r.IP, rdpPort)
		case r.TCPOpen:
			// Something is listening, but it did not complete an RDP
			// handshake. Reported, not counted as an RDP host.
			nonRDPIP = append(nonRDPIP, r.IP)
			fmt.Printf("[!] %s:%s open, no RDP handshake (%s)\n", r.IP, rdpPort, r.Detail)
		}
	}

	fmt.Printf("[+] Scan complete\n")
	fmt.Printf("[+] %d RDP host(s) found\n", len(openIPs))
	if len(nonRDPIP) > 0 {
		fmt.Printf("[!] %d host(s) with %s/tcp open that did not speak RDP\n", len(nonRDPIP), rdpPort)
	}

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
  -t, --timeout     Per-host timeout for the TCP connect and the RDP
                    handshake that follows it (default: 5s, e.g., 500ms, 5s)
  --max-cidr        Skip CIDRs smaller than this prefix (e.g., 20 skips /20 and larger networks)
  -h, --help        Show this help message

Input file format:
  One CIDR per line, e.g.:
    1.0.1.0/24
    1.0.2.0/23
  
  Lines starting with # are comments.
  Blank lines are ignored.
  Malformed entries are skipped with a warning.
  IPv6 entries are skipped as unsupported (this scanner is IPv4-only).

Detection:
  A host counts as OPEN only when it answers an RDP X.224 Connection
  Request with a valid X.224 Connection Confirm. Hosts that accept the
  TCP connection but do not speak RDP are reported separately as
  "open, no RDP handshake" and are not written to the output file.

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

		cidr, err := parseCIDR(line)
		if err != nil {
			// A valid IPv6 range is unsupported input, not broken input:
			// say which one it actually is.
			if errors.Is(err, errIPv6Unsupported) {
				fmt.Fprintf(os.Stderr, "[!] Skipping %s - %v\n", line, err)
			} else {
				fmt.Fprintf(os.Stderr, "[!] Skipping malformed CIDR %q - %v\n", line, err)
			}
			continue
		}

		// Skip large CIDRs if maxCIDR is set
		if maxCIDR > 0 && cidr.Mask < maxCIDR {
			totalIPs := uint64(1) << uint(32-cidr.Mask)
			fmt.Fprintf(os.Stderr, "[!] Skipping %s/%d (%d IPs) - use --max-cidr to change threshold\n",
				cidr.IP.String(), cidr.Mask, totalIPs)
			continue
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs, scanner.Err()
}

// parseCIDR parses "a.b.c.d/n" into a CIDR. It returns errIPv6Unsupported for
// valid IPv6 input and a descriptive error for anything genuinely malformed.
// The network address is normalised so host bits in the input (10.0.0.5/24)
// cannot shift the expansion outside the intended range.
func parseCIDR(s string) (CIDR, error) {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return CIDR{}, fmt.Errorf("expected <ip>/<prefix>, e.g. 10.0.0.0/24")
	}
	ip := net.ParseIP(parts[0])
	if ip == nil {
		return CIDR{}, fmt.Errorf("%q is not a valid IP address", parts[0])
	}
	// Checked before the prefix so that IPv6 (whose prefixes usually exceed 32)
	// is reported as unsupported rather than as an out-of-range prefix.
	if ip.To4() == nil || strings.ContainsRune(parts[0], ':') {
		return CIDR{}, errIPv6Unsupported
	}
	mask, err := strconv.Atoi(parts[1])
	if err != nil {
		return CIDR{}, fmt.Errorf("prefix %q is not a number", parts[1])
	}
	if mask < 0 || mask > 32 {
		return CIDR{}, fmt.Errorf("prefix /%d out of range for IPv4 (0-32)", mask)
	}
	return CIDR{IP: ip.To4().Mask(net.CIDRMask(mask, 32)), Mask: mask}, nil
}

// expandCIDRs expands CIDR ranges to unique IP addresses.
//
// Expansion is single-threaded, so the set and the counters are plain values.
// The previous mutex/atomic dance protected nothing and, worse, the progress
// line read a counter nobody ever incremented, so it always printed 0.
func expandCIDRs(cidrs []CIDR) ([]string, error) {
	// Use a map for deduplication
	ipSet := make(map[string]struct{})
	var totalIPs int64
	var lastReported int64

	for _, cidr := range cidrs {
		hostBits := 32 - cidr.Mask
		count := uint64(1) << uint(hostBits)

		current := ipToBigInt(cidr.IP)
		one := big.NewInt(1)

		for i := uint64(0); i < count; i++ {
			ipSet[bigIntToIP(current)] = struct{}{}
			current.Add(current, one)
		}
		totalIPs += int64(count)

		// Report at most once per expandProgressEvery IPs. Comparing against the
		// last report (instead of testing an exact multiple) keeps the line from
		// being skipped when one CIDR is larger than the reporting interval.
		if totalIPs-lastReported >= expandProgressEvery {
			lastReported = totalIPs
			fmt.Fprintf(os.Stderr, "[*] Expanding... %d IPs (%d unique so far)\n", totalIPs, len(ipSet))
		}
	}

	// Convert map to sorted slice
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
	// Pad to 4 bytes
	if len(bytes) < 4 {
		padded := make([]byte, 4)
		copy(padded[4-len(bytes):], bytes)
		bytes = padded
	}
	return fmt.Sprintf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3])
}

// x224ConnectionRequest returns an RDP X.224 Connection Request PDU
// (MS-RDPBCGR 2.2.1.1) carrying an RDP Negotiation Request for TLS|CredSSP.
//
// This is what a real RDP client sends first, and a real RDP listener answers
// it with an X.224 Connection Confirm - which is a far stronger signal than
// "something accepted the TCP connection" or "something sent bytes".
func x224ConnectionRequest() []byte {
	return []byte{
		// TPKT header: version 3, reserved 0, total length 19
		0x03, 0x00, 0x00, 0x13,
		// X.224 CR TPDU: LI=14, code=0xE0, DST-REF=0, SRC-REF=0, class=0
		0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
		// RDP Negotiation Request: type=0x01, flags=0x00, length=8,
		// requestedProtocols=0x00000003 (PROTOCOL_SSL|PROTOCOL_HYBRID)
		0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
	}
}

// isX224ConnectionConfirm validates a complete TPKT packet (header included)
// and reports whether it is an X.224 Connection Confirm, optionally carrying
// an RDP Negotiation Response (0x02) or Negotiation Failure (0x03) - both of
// which still mean "RDP is on the other end".
func isX224ConnectionConfirm(pkt []byte) (bool, string) {
	if len(pkt) < minTPKTLen {
		return false, fmt.Sprintf("response too short (%d bytes)", len(pkt))
	}
	if pkt[0] != tpktVersion {
		return false, fmt.Sprintf("not TPKT (version 0x%02X)", pkt[0])
	}
	pktLen := int(pkt[2])<<8 | int(pkt[3])
	if pktLen < minTPKTLen || pktLen > maxTPKTLen {
		return false, fmt.Sprintf("implausible TPKT length %d", pktLen)
	}
	if pktLen > len(pkt) {
		return false, fmt.Sprintf("truncated TPKT (declared %d, got %d)", pktLen, len(pkt))
	}
	// Check the TPDU code before the length indicator: "X.224 Data, not a
	// Connection Confirm" is a more useful answer than "bad length" when the
	// peer is speaking X.224 but not the RDP handshake.
	code := pkt[tpktHeaderLen+1]
	if code&0xF0 != x224CodeCC {
		return false, fmt.Sprintf("X.224 TPDU 0x%02X, not Connection Confirm (0xD0)", code)
	}
	li := int(pkt[tpktHeaderLen])
	if li < minX224LI || li > pktLen-tpktHeaderLen-1 {
		return false, fmt.Sprintf("bad X.224 length indicator %d", li)
	}
	return true, "X.224 Connection Confirm"
}

// describeErr turns a probe error into a short reason.
//
// Deadline misses arrive wrapped in a *net.OpError, so errors.As plus
// net.Error.Timeout() is the only reliable test - comparing the error against
// os.ErrDeadlineExceeded with == never matches.
func describeErr(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, io.EOF):
		return "closed without a response"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "truncated response"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout waiting for RDP handshake"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		// e.g. "connection refused", "no route to host", "connection reset by peer"
		return opErr.Err.Error()
	}
	return err.Error()
}

// probeRDP decides whether the service at addr speaks RDP: connect, send an
// X.224 Connection Request, require a valid X.224 Connection Confirm back.
// The same timeout bounds both the connect and the handshake, so a host that
// accepts connections but never answers cannot stall the scan.
func probeRDP(ip, addr string, timeout time.Duration) ScanResult {
	result := ScanResult{IP: ip}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		result.Detail = describeErr(err)
		return result
	}
	defer conn.Close()
	result.TCPOpen = true

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		result.Detail = describeErr(err)
		return result
	}

	if _, err := conn.Write(x224ConnectionRequest()); err != nil {
		result.Detail = "handshake: " + describeErr(err)
		return result
	}

	var hdr [tpktHeaderLen]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		result.Detail = "handshake: " + describeErr(err)
		return result
	}
	if hdr[0] != tpktVersion {
		// Anything that answers with its own banner (SSH, HTTP, SMTP, ...)
		// fails here: the port is open, but it is not RDP.
		result.Detail = fmt.Sprintf("not a TPKT response (first byte 0x%02X)", hdr[0])
		return result
	}
	pktLen := int(hdr[2])<<8 | int(hdr[3])
	if pktLen < minTPKTLen || pktLen > maxTPKTLen {
		result.Detail = fmt.Sprintf("implausible TPKT length %d", pktLen)
		return result
	}
	pkt := make([]byte, pktLen)
	copy(pkt, hdr[:])
	if _, err := io.ReadFull(conn, pkt[tpktHeaderLen:]); err != nil {
		result.Detail = "handshake: " + describeErr(err)
		return result
	}

	result.Open, result.Detail = isX224ConnectionConfirm(pkt)
	return result
}

// scanIPs probes every IP on TCP/3389 with at most concurrency probes in
// flight. Each goroutine writes only its own results[idx] slot and wg.Wait()
// happens-before the caller reads the slice, so no mutex is needed here.
func scanIPs(ips []string, concurrency int, timeout time.Duration) []ScanResult {
	var wg sync.WaitGroup
	results := make([]ScanResult, len(ips))
	var processed atomic.Int64
	total := int64(len(ips))

	// Create semaphore for bounded concurrency
	sem := make(chan struct{}, concurrency)

	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = probeRDP(ipAddr, net.JoinHostPort(ipAddr, rdpPort), timeout)

			// Print progress every 500 or at completion
			if done := processed.Add(1); done%500 == 0 || done == total {
				fmt.Printf("[*] Progress: %d/%d (%.1f%%)\n", done, total, float64(done)/float64(total)*100)
			}
		}(i, ip)
	}

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
