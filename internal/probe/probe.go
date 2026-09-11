// Package probe performs the TCP connect and X.224 RDP negotiation
// fingerprint against a single address.
package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Port is the default RDP service port.
const Port = 3389

// X224ConnReq is the 19-byte X.224 Connection Request carrying an
// RDP_NEG_REQ with protocol bits 0x00000000.
var X224ConnReq = []byte{
	0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// Result holds the probe result for one address.
type Result struct {
	IP   string
	Port int
	Open bool   // TCP accepted
	RDP  bool   // X.224 negotiation succeeded
	NLA  string // "not-enforced", "required", "hybrid-ex", "unknown"
	RTT  time.Duration
	Time time.Time
	Err  string
}

// Probe performs a TCP connect to ip:port with the given timeout and, on
// success, the X.224 RDP negotiation handshake to classify the service:
//
//  1. TCP connect (dial carries the timeout; a black-holed SYN fails
//     within the timeout, not after kernel retry exhaustion).
//  2. Write the 19-byte X.224 Connection Request.
//  3. Read up to 64 bytes with the same deadline.
//  4. If the response starts with 0x03 and byte 5 is 0xD0 (X.224 DR),
//     parse the RDP negotiation header: RDP_NEG_RSP (0x02) carries the
//     selected protocol little-endian in bytes 15..18
//     (0x0 not-enforced, 0x2 required, 0x8 hybrid-ex).
//  5. Any read/write failure after connect keeps Open=true, RDP=false,
//     with a short "fingerprint failed: ..." reason.
func Probe(ctx context.Context, ip string, port int, timeout time.Duration) Result {
	res := Result{IP: ip, Port: port, NLA: "unknown"}
	start := time.Now()
	res.Time = start

	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip, itoa(port)))
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

	if _, err := conn.Write(X224ConnReq); err != nil {
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

// shortReason maps an error to a short, printable reason.
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

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
