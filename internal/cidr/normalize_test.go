package cidr

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, s string) CIDR {
	t.Helper()
	c, ok := ParseCIDR(s)
	if !ok {
		t.Fatalf("bad test CIDR %q", s)
	}
	return c
}

func TestNormalizeDisjointPassthrough(t *testing.T) {
	ranges := Normalize([]CIDR{mustCIDR(t, "10.0.2.0/24"), mustCIDR(t, "10.0.0.0/24")})
	if len(ranges) != 2 {
		t.Fatalf("got %d ranges, want 2: %+v", len(ranges), ranges)
	}
	// sorted by start
	if ranges[0].Start != IPToUint32(net.IPv4(10, 0, 0, 0)) ||
		ranges[1].Start != IPToUint32(net.IPv4(10, 0, 2, 0)) {
		t.Fatalf("ranges not sorted: %+v", ranges)
	}
	if got := TotalIPs(ranges); got != 512 {
		t.Errorf("TotalIPs = %d, want 512", got)
	}
}

func TestNormalizeOverlappingMerge(t *testing.T) {
	ranges := Normalize([]CIDR{mustCIDR(t, "10.0.0.0/24"), mustCIDR(t, "10.0.0.128/25")})
	if len(ranges) != 1 {
		t.Fatalf("got %d ranges, want 1: %+v", len(ranges), ranges)
	}
	if ranges[0] != (Range{Start: IPToUint32(net.IPv4(10, 0, 0, 0)), End: IPToUint32(net.IPv4(10, 0, 0, 255))}) {
		t.Errorf("merged range = %+v, want 10.0.0.0-10.0.0.255", ranges[0])
	}
	if got := TotalIPs(ranges); got != 256 {
		t.Errorf("TotalIPs = %d, want 256", got)
	}
}

func TestNormalizeAdjacentMerge(t *testing.T) {
	ranges := Normalize([]CIDR{mustCIDR(t, "10.0.1.0/24"), mustCIDR(t, "10.0.0.0/24")})
	if len(ranges) != 1 {
		t.Fatalf("got %d ranges, want 1: %+v", len(ranges), ranges)
	}
	if ranges[0] != (Range{Start: IPToUint32(net.IPv4(10, 0, 0, 0)), End: IPToUint32(net.IPv4(10, 0, 1, 255))}) {
		t.Errorf("merged range = %+v, want 10.0.0.0-10.0.1.255", ranges[0])
	}
	if got := TotalIPs(ranges); got != 512 {
		t.Errorf("TotalIPs = %d, want 512", got)
	}
}

func TestNormalizeSuperset(t *testing.T) {
	ranges := Normalize([]CIDR{mustCIDR(t, "10.0.2.0/24"), mustCIDR(t, "10.0.0.0/16")})
	if len(ranges) != 1 || TotalIPs(ranges) != 65536 {
		t.Fatalf("got %+v, want single /16", ranges)
	}
}

func TestNormalizeHostBitsCleared(t *testing.T) {
	ranges := Normalize([]CIDR{mustCIDR(t, "10.0.0.5/24")})
	if len(ranges) != 1 || ranges[0].Start != IPToUint32(net.IPv4(10, 0, 0, 0)) {
		t.Fatalf("host bits not cleared: %+v", ranges)
	}
}

func TestNormalizeSlashZero(t *testing.T) {
	ranges := Normalize([]CIDR{mustCIDR(t, "0.0.0.0/0")})
	if len(ranges) != 1 {
		t.Fatalf("got %d ranges, want 1: %+v", len(ranges), ranges)
	}
	if ranges[0].Start != 0 || ranges[0].End != ^uint32(0) {
		t.Errorf("/0 range = %+v, want 0.0.0.0-255.255.255.255", ranges[0])
	}
	if got := TotalIPs(ranges); got != 1<<32 {
		t.Errorf("TotalIPs(/0) = %d, want %d", got, uint64(1)<<32)
	}
}

func TestNormalizeSlash32(t *testing.T) {
	ranges := Normalize([]CIDR{mustCIDR(t, "1.2.3.4/32")})
	if len(ranges) != 1 {
		t.Fatalf("got %d ranges, want 1", len(ranges))
	}
	want := IPToUint32(net.IPv4(1, 2, 3, 4))
	if ranges[0].Start != want || ranges[0].End != want {
		t.Errorf("/32 range = %+v, want single 1.2.3.4", ranges[0])
	}
}

func TestNormalizeNoOverlapNoAdjacent(t *testing.T) {
	cidrs := []CIDR{
		mustCIDR(t, "10.0.0.0/25"),
		mustCIDR(t, "10.0.0.128/25"), // adjacent to first, merges
		mustCIDR(t, "10.0.1.0/32"),   // adjacent to merged, merges
		mustCIDR(t, "10.0.3.0/24"),   // disjoint (10.0.2.x gap)
	}
	ranges := Normalize(cidrs)
	if len(ranges) != 2 {
		t.Fatalf("got %d ranges, want 2: %+v", len(ranges), ranges)
	}
	if TotalIPs(ranges) != 256+1+256 {
		t.Errorf("TotalIPs = %d, want 513", TotalIPs(ranges))
	}
	for i := 1; i < len(ranges); i++ {
		if ranges[i].Start <= ranges[i-1].End+1 {
			t.Errorf("ranges %d and %d overlap or are adjacent: %+v", i-1, i, ranges)
		}
	}
}

func TestRawAddressCount(t *testing.T) {
	cidrs := []CIDR{mustCIDR(t, "10.0.0.0/24"), mustCIDR(t, "10.0.1.0/24")}
	if got := RawAddressCount(cidrs); got != 512 {
		t.Errorf("RawAddressCount = %d, want 512", got)
	}
}
