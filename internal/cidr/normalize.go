package cidr

import "sort"

// Range is an inclusive [Start, End] pair of uint32 IPv4 addresses.
type Range struct {
	Start, End uint32
}

// Normalize converts CIDRs to a sorted, disjoint list of inclusive
// ranges, merging overlapping and adjacent ones. Host bits in the input
// addresses are cleared (a /24 is always its network address). Memory is
// O(number of CIDRs), not O(number of IPs), and deduplication becomes
// unnecessary downstream because the resulting ranges are disjoint.
func Normalize(cidrs []CIDR) []Range {
	type raw struct{ start, end uint32 }
	raws := make([]raw, 0, len(cidrs))
	for _, c := range cidrs {
		hostBits := uint(32 - c.Mask)
		start := IPToUint32(c.IP) & (^uint32(0) << hostBits)
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

// TotalIPs returns the number of unique addresses covered by the ranges.
func TotalIPs(ranges []Range) uint64 {
	var total uint64
	for _, r := range ranges {
		total += uint64(r.End-r.Start) + 1
	}
	return total
}

// RawAddressCount is the pre-merge address count, for diagnostics only.
func RawAddressCount(cidrs []CIDR) uint64 {
	var total uint64
	for _, c := range cidrs {
		total += uint64(1) << uint(32-c.Mask)
	}
	return total
}
