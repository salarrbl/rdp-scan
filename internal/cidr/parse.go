// Package cidr parses CIDR input files and normalizes ranges to
// disjoint uint32 address intervals.
package cidr

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// CIDR represents a parsed CIDR range
type CIDR struct {
	IP   net.IP
	Mask int
}

// ParseCIDR parses a single "a.b.c.d/len" line. It returns false for
// anything that is not a valid IPv4 CIDR.
func ParseCIDR(s string) (CIDR, bool) {
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

// ReadCIDRs reads CIDR ranges from filename. Blank lines and lines
// starting with # are ignored; malformed lines and, when maxCIDR > 0,
// CIDRs whose prefix is smaller than maxCIDR are skipped with a note on
// warnings. The scanner buffer is capped at 64KB (CIDR lines are short).
func ReadCIDRs(filename string, maxCIDR int, warnings io.Writer) ([]CIDR, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cidrs []CIDR
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 4*1024)
	scanner.Buffer(buf, 64*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and blank lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if cidr, ok := ParseCIDR(line); ok {
			// Skip CIDRs with prefix strictly smaller than maxCIDR
			if maxCIDR > 0 && cidr.Mask < maxCIDR {
				size := uint64(1) << uint(32-cidr.Mask)
				fmt.Fprintf(warnings, "[!] Skipping %s/%d (%d IPs) - use --max-cidr to change threshold\n",
					cidr.IP.String(), cidr.Mask, size)
				continue
			}
			cidrs = append(cidrs, cidr)
		} else {
			fmt.Fprintf(warnings, "[!] Skipping malformed CIDR: %s\n", line)
		}
	}
	return cidrs, scanner.Err()
}
