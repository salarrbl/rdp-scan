package cidr

import (
	"net"
	"sort"
	"testing"
)

func TestIPToUint32(t *testing.T) {
	cases := map[string]uint32{
		"0.0.0.0":         0,
		"1.0.0.0":         1 << 24,
		"0.1.0.0":         1 << 16,
		"0.0.1.0":         1 << 8,
		"0.0.0.1":         1,
		"1.2.3.4":         0x01020304,
		"255.255.255.255": ^uint32(0),
	}
	for ip, want := range cases {
		if got := IPToUint32(net.ParseIP(ip)); got != want {
			t.Errorf("IPToUint32(%s) = %#x, want %#x", ip, got, want)
		}
	}
}

func TestUint32ToIP(t *testing.T) {
	cases := map[uint32]string{
		0:          "0.0.0.0",
		1 << 24:    "1.0.0.0",
		0x01020304: "1.2.3.4",
		^uint32(0): "255.255.255.255",
		0x7f000001: "127.0.0.1",
	}
	for n, want := range cases {
		if got := Uint32ToIP(n); got != want {
			t.Errorf("Uint32ToIP(%#x) = %q, want %q", n, got, want)
		}
	}
}

func TestIPRoundTrip(t *testing.T) {
	ips := []string{"0.0.0.0", "127.0.0.1", "10.255.255.254", "172.16.0.1", "255.255.255.255"}
	for _, s := range ips {
		if got := Uint32ToIP(IPToUint32(net.ParseIP(s))); got != s {
			t.Errorf("round trip %s -> %s", s, got)
		}
	}
}

// TestNumericOrderIsSane documents that uint32 ordering matches
// human-sensible IP ordering (unlike lexicographic string ordering).
func TestNumericOrderIsSane(t *testing.T) {
	ips := []string{"1.12.11.1", "1.12.100.1", "1.12.9.1"}
	ns := make([]uint32, len(ips))
	for i, s := range ips {
		ns[i] = IPToUint32(net.ParseIP(s))
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i] < ns[j] })
	want := []string{"1.12.9.1", "1.12.11.1", "1.12.100.1"}
	for i, s := range want {
		if got := Uint32ToIP(ns[i]); got != s {
			t.Errorf("sorted[%d] = %s, want %s", i, got, s)
		}
	}
}
