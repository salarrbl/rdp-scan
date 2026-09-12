package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// captureStderr runs fn with os.Stderr redirected to a pipe and returns
// everything written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	out := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		out <- buf.String()
	}()
	fn()
	// Close the write end first and only drain/close the read end once the
	// copying goroutine has seen EOF, otherwise output gets truncated.
	w.Close()
	os.Stderr = old
	s := <-out
	r.Close()
	return s
}

// fakeListener starts a loopback listener whose connections are handled by fn.
// The listener is closed when the test finishes.
func fakeListener(t *testing.T, fn func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go fn(conn)
		}
	}()
	return ln.Addr().String()
}

// mustCIDR parses a CIDR or fails the test.
func mustCIDR(t *testing.T, s string) CIDR {
	t.Helper()
	c, err := parseCIDR(s)
	if err != nil {
		t.Fatalf("parseCIDR(%q): %v", s, err)
	}
	return c
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// ---------------------------------------------------------------------------
// parseCIDR / readCIDRs  (bug #4: IPv6 was reported as "malformed")
// ---------------------------------------------------------------------------

func TestParseCIDRValid(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		mask int
	}{
		{"10.0.0.0/24", "10.0.0.0", 24},
		{"  192.168.0.0/16  ", "192.168.0.0", 16},
		{"1.2.3.4/32", "1.2.3.4", 32},
		{"0.0.0.0/0", "0.0.0.0", 0},
		// Host bits must be masked off, otherwise the expansion drifts past the
		// end of the range (10.0.0.5/24 would start at .5 and spill into .256).
		{"10.0.0.5/24", "10.0.0.0", 24},
		{"192.168.1.130/25", "192.168.1.128", 25},
	}
	for _, tc := range cases {
		cidr, err := parseCIDR(tc.in)
		if err != nil {
			t.Errorf("parseCIDR(%q) returned error: %v", tc.in, err)
			continue
		}
		if got := cidr.IP.String(); got != tc.ip {
			t.Errorf("parseCIDR(%q) IP = %s, want %s", tc.in, got, tc.ip)
		}
		if cidr.Mask != tc.mask {
			t.Errorf("parseCIDR(%q) Mask = %d, want %d", tc.in, cidr.Mask, tc.mask)
		}
		if cidr.IP.To4() == nil {
			t.Errorf("parseCIDR(%q) did not return a 4-byte IP", tc.in)
		}
	}
}

func TestParseCIDRInvalid(t *testing.T) {
	cases := []struct {
		in        string
		wantIPv6  bool
		wantInMsg string
	}{
		// Valid IPv6 -> unsupported, never "malformed".
		{"2001:db8::/32", true, ""},
		{"::1/128", true, ""},
		{"fe80::/10", true, ""},
		{"2a00:1450:400a:803::200e/64", true, ""},
		{"::ffff:192.0.2.1/120", true, ""}, // IPv4-mapped, but still IPv6 notation
		// Genuinely broken input.
		{"10.0.0.0", false, "expected <ip>/<prefix>"},
		{"not-a-cidr", false, "expected <ip>/<prefix>"},
		{"", false, "expected <ip>/<prefix>"},
		{"999.1.1.1/24", false, "not a valid IP address"},
		{"10.0.0.0/33", false, "out of range for IPv4"},
		{"10.0.0.0/-1", false, "out of range for IPv4"},
		{"10.0.0.0/abc", false, "not a number"},
		{"10.0.0.0/24/8", false, "not a number"},
		{"10.0.0.0 /24", false, "not a valid IP address"},
	}
	for _, tc := range cases {
		cidr, err := parseCIDR(tc.in)
		if err == nil {
			t.Errorf("parseCIDR(%q) = %v, want error", tc.in, cidr)
			continue
		}
		if got := errors.Is(err, errIPv6Unsupported); got != tc.wantIPv6 {
			t.Errorf("parseCIDR(%q): errors.Is(err, errIPv6Unsupported) = %v, want %v (err: %v)",
				tc.in, got, tc.wantIPv6, err)
		}
		if !tc.wantIPv6 && tc.wantInMsg != "" && !strings.Contains(err.Error(), tc.wantInMsg) {
			t.Errorf("parseCIDR(%q) error = %q, want it to contain %q", tc.in, err, tc.wantInMsg)
		}
	}
}

func TestReadCIDRsDistinguishesIPv6FromMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ranges.txt")
	content := strings.Join([]string{
		"# a comment",
		"",
		"10.0.0.0/24",
		"2001:db8::/32",
		"::1/128",
		"nonsense",
		"10.0.0.0/33",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var cidrs []CIDR
	stderr := captureStderr(t, func() {
		var err error
		cidrs, err = readCIDRs(path, 0)
		if err != nil {
			t.Fatalf("readCIDRs: %v", err)
		}
	})

	if len(cidrs) != 1 {
		t.Fatalf("readCIDRs kept %d CIDRs, want 1: %v", len(cidrs), cidrs)
	}
	if got := cidrs[0].IP.String(); got != "10.0.0.0" {
		t.Errorf("kept CIDR = %s, want 10.0.0.0", got)
	}

	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	var v6Lines, malformedLines []string
	for _, l := range lines {
		switch {
		case strings.Contains(l, "malformed"):
			malformedLines = append(malformedLines, l)
		case strings.Contains(l, "IPv6"):
			v6Lines = append(v6Lines, l)
		}
	}
	if len(v6Lines) != 2 {
		t.Errorf("want 2 'IPv6 not supported' lines, got %d:\n%s", len(v6Lines), stderr)
	}
	if len(malformedLines) != 2 {
		t.Errorf("want 2 'malformed' lines, got %d:\n%s", len(malformedLines), stderr)
	}
	for _, l := range v6Lines {
		if strings.Contains(l, "malformed") {
			t.Errorf("IPv6 line still called malformed: %q", l)
		}
	}
	// The malformed lines must be about the actually-broken entries.
	for _, want := range []string{"nonsense", "10.0.0.0/33"} {
		found := false
		for _, l := range malformedLines {
			if strings.Contains(l, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no malformed-CIDR line mentions %q:\n%s", want, stderr)
		}
	}
	for _, bad := range []string{"2001:db8::/32", "::1/128"} {
		for _, l := range malformedLines {
			if strings.Contains(l, bad) {
				t.Errorf("%q reported as malformed:\n%s", bad, stderr)
			}
		}
	}
}

func TestReadCIDRsMaxCIDRFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ranges.txt")
	if err := os.WriteFile(path, []byte("10.0.0.0/16\n10.1.0.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var cidrs []CIDR
	captureStderr(t, func() {
		var err error
		cidrs, err = readCIDRs(path, 24)
		if err != nil {
			t.Fatalf("readCIDRs: %v", err)
		}
	})
	if len(cidrs) != 1 || cidrs[0].Mask != 24 {
		t.Fatalf("--max-cidr 24 kept %v, want only the /24", cidrs)
	}
}

// ---------------------------------------------------------------------------
// expandCIDRs  (bugs #2 and #3: dead counter + pointless locking)
// ---------------------------------------------------------------------------

func TestExpandCIDRsDedupAndCount(t *testing.T) {
	cidrs := []CIDR{
		mustCIDR(t, "192.0.2.0/29"),    // 8 IPs
		mustCIDR(t, "192.0.2.4/30"),    // 4 IPs, all inside the /29
		mustCIDR(t, "198.51.100.0/31"), // 2 IPs
	}

	var ips []string
	stderr := captureStderr(t, func() {
		var err error
		ips, err = expandCIDRs(cidrs)
		if err != nil {
			t.Fatalf("expandCIDRs: %v", err)
		}
	})

	if len(ips) != 10 {
		t.Fatalf("expandCIDRs returned %d unique IPs, want 10: %v", len(ips), ips)
	}
	sort.Strings(ips)
	want := []string{
		"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3",
		"192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7",
		"198.51.100.0", "198.51.100.1",
	}
	if strings.Join(ips, ",") != strings.Join(want, ",") {
		t.Errorf("expandCIDRs = %v, want %v", ips, want)
	}
	if !strings.Contains(stderr, "Expanded 14 total IPs from 3 CIDRs") {
		t.Errorf("summary line wrong:\n%s", stderr)
	}
}

// TestExpandCIDRsProgressReportsRealCount is the regression test for the
// progress line that used to read a counter nobody incremented, so it always
// printed "0 unique IPs so far".
func TestExpandCIDRsProgressReportsRealCount(t *testing.T) {
	cidrs := []CIDR{mustCIDR(t, "198.18.0.0/16")} // 65536 IPs, > expandProgressEvery

	var ips []string
	stderr := captureStderr(t, func() {
		var err error
		ips, err = expandCIDRs(cidrs)
		if err != nil {
			t.Fatalf("expandCIDRs: %v", err)
		}
	})

	if len(ips) != 65536 {
		t.Fatalf("expandCIDRs returned %d IPs, want 65536", len(ips))
	}

	re := regexp.MustCompile(`\[\*\] Expanding\.\.\. (\d+) IPs \((\d+) unique so far\)`)
	matches := re.FindAllStringSubmatch(stderr, -1)
	if len(matches) == 0 {
		t.Fatalf("no progress line emitted:\n%s", stderr)
	}
	for _, m := range matches {
		if m[1] == "0" || m[2] == "0" {
			t.Errorf("progress line reports zero progress: %q", m[0])
		}
	}
	last := matches[len(matches)-1]
	if last[1] != "65536" || last[2] != "65536" {
		t.Errorf("final progress line = %q, want 65536 IPs (65536 unique so far)", last[0])
	}
	if ips[0] == "" || ips[65535] == "" {
		t.Errorf("empty IP in expansion")
	}
}

func TestExpandCIDRsSingleCIDRDoesNotSkipProgress(t *testing.T) {
	// One CIDR larger than the reporting interval: the old "%50000 == 0" test
	// could step straight over every multiple and print nothing at all.
	cidrs := []CIDR{mustCIDR(t, "203.0.113.0/23")} // 512 IPs x 200 copies
	for i := 0; i < 199; i++ {
		cidrs = append(cidrs, mustCIDR(t, "203.0.113.0/24"))
	}
	stderr := captureStderr(t, func() {
		if _, err := expandCIDRs(cidrs); err != nil {
			t.Fatalf("expandCIDRs: %v", err)
		}
	})
	if !strings.Contains(stderr, "Expanding...") {
		t.Errorf("expected at least one progress line:\n%s", stderr)
	}
	// 512 + 199*256
	if !strings.Contains(stderr, "Expanded 51456 total IPs from 200 CIDRs") {
		t.Errorf("unexpected summary:\n%s", stderr)
	}
}

func TestBigIntRoundTrip(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "1.2.3.4", "10.0.0.255", "255.255.255.255"} {
		if got := bigIntToIP(ipToBigInt(net.ParseIP(s))); got != s {
			t.Errorf("round trip %s -> %s", s, got)
		}
	}
}

// ---------------------------------------------------------------------------
// X.224 handshake validation  (bug #1)
// ---------------------------------------------------------------------------

func TestX224ConnectionRequestShape(t *testing.T) {
	req := x224ConnectionRequest()
	want := mustHex(t, "03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 03 00 00 00")
	if !bytes.Equal(req, want) {
		t.Fatalf("Connection Request = % x\nwant                    % x", req, want)
	}
	if len(req) != int(req[2])<<8|int(req[3]) {
		t.Errorf("TPKT length field %d != actual %d", int(req[2])<<8|int(req[3]), len(req))
	}
	if req[4]+1 != 15 { // LI counts the octets that follow it
		t.Errorf("X.224 length indicator %d inconsistent with packet", req[4])
	}
	if req[5] != 0xE0 {
		t.Errorf("TPDU code = 0x%02X, want 0xE0 (Connection Request)", req[5])
	}
}

func TestIsX224ConnectionConfirm(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want bool
	}{
		{
			name: "CC with RDP Negotiation Response (what Windows sends)",
			hex:  "03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 02 00 00 00",
			want: true,
		},
		{
			name: "CC with RDP Negotiation Failure - still an RDP listener",
			hex:  "03 00 00 13 0e d0 00 00 12 34 00 03 00 08 00 02 00 00 00",
			want: true,
		},
		{
			name: "legacy CC without negotiation data",
			hex:  "03 00 00 0b 06 d0 00 00 12 34 00",
			want: true,
		},
		{
			name: "CC with non-zero credit nibble",
			hex:  "03 00 00 0b 06 d3 00 00 12 34 00",
			want: true,
		},
		{
			name: "echoed Connection Request is not a Confirm",
			hex:  "03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 03 00 00 00",
			want: false,
		},
		{
			name: "X.224 Data TPDU",
			hex:  "03 00 00 07 02 f0 80",
			want: false,
		},
		{
			name: "X.224 Disconnect Request",
			hex:  "03 00 00 09 04 80 00 00 00",
			want: false,
		},
		{
			name: "declared length longer than buffer",
			hex:  "03 00 00 13 0e d0 00 00",
			want: false,
		},
		{
			name: "length indicator too small",
			hex:  "03 00 00 07 02 d0 00",
			want: false,
		},
		{
			name: "empty",
			hex:  "",
			want: false,
		},
	}
	for _, tc := range cases {
		pkt := mustHex(t, tc.hex)
		got, detail := isX224ConnectionConfirm(pkt)
		if got != tc.want {
			t.Errorf("%s: isX224ConnectionConfirm(% x) = %v (%s), want %v", tc.name, pkt, got, detail, tc.want)
			continue
		}
		if tc.want && detail != "X.224 Connection Confirm" {
			t.Errorf("%s: detail = %q, want %q", tc.name, detail, "X.224 Connection Confirm")
		}
		if !tc.want && detail == "" {
			t.Errorf("%s: rejection has no explanation", tc.name)
		}
	}

	// Non-RDP banners must be rejected with a reason that names the problem.
	for _, banner := range []string{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n",
		"HTTP/1.1 400 Bad Request\r\n\r\n",
		"220 smtp.example.com ESMTP\r\n",
	} {
		got, detail := isX224ConnectionConfirm([]byte(banner))
		if got {
			t.Errorf("banner %q accepted as RDP", banner)
		}
		if detail == "" {
			t.Errorf("banner %q rejected without a reason", banner)
		}
	}
}

func TestProbeRDPAgainstRealHandshake(t *testing.T) {
	received := make(chan []byte, 1)
	addr := fakeListener(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, len(x224ConnectionRequest()))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		received <- buf
		// Connection Confirm + RDP Negotiation Response selecting TLS.
		conn.Write(mustHex(t, "03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 02 00 00 00"))
	})

	res := probeRDP("127.0.0.1", addr, 2*time.Second)
	if !res.TCPOpen {
		t.Errorf("TCPOpen = false, want true (%s)", res.Detail)
	}
	if !res.Open {
		t.Errorf("Open = false, want true (%s)", res.Detail)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, x224ConnectionRequest()) {
			t.Errorf("server received % x, want % x", got, x224ConnectionRequest())
		}
	case <-time.After(2 * time.Second):
		t.Error("probe never sent an X.224 Connection Request")
	}
}

func TestProbeRDPClassifiesNonRDPListeners(t *testing.T) {
	// Decoded up front so the fake handlers never call t.Fatalf off the test
	// goroutine.
	halfTPKT := mustHex(t, "03 00 00 13 0e d0")
	absurdLen := mustHex(t, "03 00 ff ff")
	dataTPDU := mustHex(t, "03 00 00 07 02 f0 80")

	// drainRequest consumes the Connection Request before hanging up. Closing a
	// socket that still has unread data in its receive buffer makes the kernel
	// send RST instead of FIN, which would turn a deterministic EOF into a
	// racy "connection reset by peer".
	drainRequest := func(conn net.Conn) {
		io.ReadFull(conn, make([]byte, len(x224ConnectionRequest())))
	}

	cases := []struct {
		name       string
		handler    func(net.Conn)
		wantOpen   bool
		wantDetail string
	}{
		{
			// This is the case the old code called "OPEN": a listener that
			// accepts and closes without sending anything was treated as RDP
			// because conn.Read returned n == 0. Depending on who wins the
			// race the probe reports EOF or a reset - either way: not RDP.
			name: "closes immediately after connect",
			handler: func(conn net.Conn) {
				conn.Close()
			},
			wantOpen:   false,
			wantDetail: "",
		},
		{
			// The listener consumes our Connection Request and then hangs up
			// without answering: the old `n == 0` branch called this OPEN.
			name: "reads the request then closes without answering",
			handler: func(conn net.Conn) {
				defer conn.Close()
				drainRequest(conn)
			},
			wantOpen:   false,
			wantDetail: "closed without a response",
		},
		{
			name: "sends an SSH banner",
			handler: func(conn net.Conn) {
				defer conn.Close()
				conn.Write([]byte("SSH-2.0-OpenSSH_8.9p1\r\n"))
				time.Sleep(200 * time.Millisecond)
			},
			wantOpen:   false,
			wantDetail: "not a TPKT response",
		},
		{
			name: "sends an HTTP response",
			handler: func(conn net.Conn) {
				defer conn.Close()
				conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
				time.Sleep(200 * time.Millisecond)
			},
			wantOpen:   false,
			wantDetail: "not a TPKT response",
		},
		{
			name: "accepts and stays silent",
			handler: func(conn net.Conn) {
				defer conn.Close()
				time.Sleep(3 * time.Second)
			},
			wantOpen:   false,
			wantDetail: "timeout waiting for RDP handshake",
		},
		{
			name: "sends half a TPKT packet then closes",
			handler: func(conn net.Conn) {
				defer conn.Close()
				drainRequest(conn)
				conn.Write(halfTPKT)
			},
			wantOpen:   false,
			wantDetail: "truncated response",
		},
		{
			name: "claims an absurd TPKT length",
			handler: func(conn net.Conn) {
				defer conn.Close()
				drainRequest(conn)
				conn.Write(absurdLen)
			},
			wantOpen:   false,
			wantDetail: "implausible TPKT length",
		},
		{
			name: "answers with an X.224 Data TPDU",
			handler: func(conn net.Conn) {
				defer conn.Close()
				drainRequest(conn)
				conn.Write(dataTPDU)
			},
			wantOpen:   false,
			wantDetail: "X.224 TPDU 0xF0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := fakeListener(t, tc.handler)
			res := probeRDP("127.0.0.1", addr, 300*time.Millisecond)
			if !res.TCPOpen {
				t.Errorf("TCPOpen = false, want true (%s)", res.Detail)
			}
			if res.Open != tc.wantOpen {
				t.Errorf("Open = %v, want %v (%s)", res.Open, tc.wantOpen, res.Detail)
			}
			if tc.wantDetail != "" && !strings.Contains(res.Detail, tc.wantDetail) {
				t.Errorf("Detail = %q, want it to contain %q", res.Detail, tc.wantDetail)
			}
			if res.IP != "127.0.0.1" {
				t.Errorf("IP = %q, want 127.0.0.1", res.IP)
			}
		})
	}
}

func TestProbeRDPClosedPort(t *testing.T) {
	// Grab a port and immediately release it: nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	res := probeRDP("127.0.0.1", addr, 500*time.Millisecond)
	if res.TCPOpen || res.Open {
		t.Errorf("closed port reported as open: %+v", res)
	}
	if !strings.Contains(res.Detail, "connection refused") {
		t.Errorf("Detail = %q, want 'connection refused'", res.Detail)
	}
}

// TestDescribeErrSeesWrappedTimeouts is the direct regression test for
// `err == os.ErrDeadlineExceeded`: conn.Read wraps deadline misses in a
// *net.OpError, so the == comparison never fired and the branch was dead.
func TestDescribeErrSeesWrappedTimeouts(t *testing.T) {
	wrapped := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}

	if wrapped == error(os.ErrDeadlineExceeded) {
		t.Fatal("precondition broken: wrapped error compares equal to os.ErrDeadlineExceeded")
	}
	if !errors.Is(wrapped, os.ErrDeadlineExceeded) {
		t.Error("errors.Is should unwrap to os.ErrDeadlineExceeded")
	}
	var netErr net.Error
	if !errors.As(wrapped, &netErr) || !netErr.Timeout() {
		t.Error("errors.As(&net.Error) + Timeout() should detect the wrapped deadline")
	}
	if got := describeErr(wrapped); !strings.Contains(got, "timeout") {
		t.Errorf("describeErr(wrapped deadline) = %q, want it to mention timeout", got)
	}
	if got := describeErr(io.EOF); got != "closed without a response" {
		t.Errorf("describeErr(io.EOF) = %q", got)
	}
	if got := describeErr(io.ErrUnexpectedEOF); got != "truncated response" {
		t.Errorf("describeErr(io.ErrUnexpectedEOF) = %q", got)
	}
	if got := describeErr(nil); got != "ok" {
		t.Errorf("describeErr(nil) = %q", got)
	}
}

func TestScanIPsKeepsResultOrder(t *testing.T) {
	ips := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"}
	results := scanIPs(ips, 3, 300*time.Millisecond)
	if len(results) != len(ips) {
		t.Fatalf("got %d results, want %d", len(results), len(ips))
	}
	for i, r := range results {
		if r.IP != ips[i] {
			t.Errorf("results[%d].IP = %q, want %q", i, r.IP, ips[i])
		}
		if r.Detail == "" {
			t.Errorf("results[%d] has no Detail", i)
		}
		if r.Open && !r.TCPOpen {
			t.Errorf("results[%d] Open without TCPOpen", i)
		}
	}
}

func TestSaveResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	if err := saveResults([]string{"10.0.0.1", "10.0.0.2"}, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "10.0.0.1\n10.0.0.2\n" {
		t.Errorf("saved %q", data)
	}
}
