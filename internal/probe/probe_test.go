package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// rdpNegReply builds a 19-byte X.224 DR carrying an RDP negotiation
// header: negType (0x02 RSP, 0x03 FAIL), len 8, proto little-endian.
func rdpNegReply(negType byte, proto uint32) []byte {
	b := make([]byte, 19)
	b[0], b[1], b[2], b[3] = 0x03, 0x00, 0x00, 0x13
	b[4] = 0x0e
	b[5] = 0xD0
	// b[6..11] refs/class zero
	b[12] = negType
	b[13], b[14] = 0x08, 0x00
	binary.LittleEndian.PutUint32(b[15:19], proto)
	return b
}

// fakeServer starts a listener on 127.0.0.1 that replies to every
// accepted connection with reply (if non-nil).
func fakeServer(t *testing.T, reply []byte) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				conn.Read(make([]byte, 64))
				if reply != nil {
					conn.Write(reply)
				}
				conn.Close()
			}()
			select {
			case <-done:
				return
			default:
			}
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return port, func() {
		close(done)
		ln.Close()
		wg.Wait()
	}
}

func TestProbeRDPSuccess(t *testing.T) {
	cases := []struct {
		name  string
		proto uint32
		nla   string
	}{
		{"not-enforced", 0x00000000, "not-enforced"},
		{"required", 0x00000002, "required"},
		{"hybrid-ex", 0x00000008, "hybrid-ex"},
		{"unknown-proto", 0x00000010, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port, stop := fakeServer(t, rdpNegReply(0x02, tc.proto))
			defer stop()
			res := Probe(context.Background(), "127.0.0.1", port, time.Second)
			if !res.Open {
				t.Fatalf("Open = false, want true (err=%q)", res.Err)
			}
			if !res.RDP {
				t.Fatalf("RDP = false, want true (err=%q)", res.Err)
			}
			if res.NLA != tc.nla {
				t.Errorf("NLA = %q, want %q", res.NLA, tc.nla)
			}
			if res.Err != "" {
				t.Errorf("Err = %q, want empty", res.Err)
			}
		})
	}
}

func TestProbeRDPNegFail(t *testing.T) {
	port, stop := fakeServer(t, rdpNegReply(0x03, 0))
	defer stop()
	res := Probe(context.Background(), "127.0.0.1", port, time.Second)
	if !res.Open {
		t.Fatal("Open = false, want true")
	}
	if res.RDP {
		t.Error("RDP = true, want false for RDP_NEG_FAIL")
	}
	if !strings.Contains(res.Err, "fingerprint failed") {
		t.Errorf("Err = %q, want fingerprint failure reason", res.Err)
	}
}

func TestProbeNonRDPService(t *testing.T) {
	// A plain HTTP server on the probed port: open but not RDP.
	reply := []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
	port, stop := fakeServer(t, reply)
	defer stop()
	res := Probe(context.Background(), "127.0.0.1", port, time.Second)
	if !res.Open {
		t.Fatal("Open = false, want true")
	}
	if res.RDP {
		t.Error("RDP = true, want false for non-RDP response")
	}
	if !strings.HasPrefix(res.Err, "fingerprint failed") {
		t.Errorf("Err = %q, want fingerprint failure prefix", res.Err)
	}
}

func TestProbeSilentPeer(t *testing.T) {
	// Peer accepts but never replies: read times out.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				time.Sleep(500 * time.Millisecond) // hold the conn open
				conn.Close()
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	res := Probe(context.Background(), "127.0.0.1", port, 150*time.Millisecond)
	if !res.Open {
		t.Fatal("Open = false, want true")
	}
	if res.RDP {
		t.Error("RDP = true, want false")
	}
	if !strings.Contains(res.Err, "timeout") {
		t.Errorf("Err = %q, want timeout reason", res.Err)
	}
}

func TestProbeClosedPort(t *testing.T) {
	// Grab a port, close the listener, probe the now-closed port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	res := Probe(context.Background(), "127.0.0.1", port, time.Second)
	if res.Open {
		t.Error("Open = true on closed port")
	}
	if res.RDP {
		t.Error("RDP = true on closed port")
	}
}

func TestProbeContextCancel(t *testing.T) {
	port, stop := fakeServer(t, rdpNegReply(0x02, 2))
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := Probe(ctx, "127.0.0.1", port, time.Second)
	if res.Open {
		t.Error("Open = true with cancelled context")
	}
	if res.Err != "cancelled" {
		t.Errorf("Err = %q, want cancelled", res.Err)
	}
}

func TestProbePortField(t *testing.T) {
	port, stop := fakeServer(t, rdpNegReply(0x02, 2))
	defer stop()
	res := Probe(context.Background(), "127.0.0.1", port, time.Second)
	if res.Port != port {
		t.Errorf("Port = %d, want %d", res.Port, port)
	}
	if res.IP != "127.0.0.1" {
		t.Errorf("IP = %q", res.IP)
	}
	if res.RTT < 0 {
		t.Errorf("RTT = %v, want >= 0", res.RTT)
	}
	fmt.Println("probe rtt:", res.RTT)
}
