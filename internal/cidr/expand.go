package cidr

import (
	"fmt"
	"net"
)

// IPToUint32 converts an IPv4 address to its uint32 representation.
func IPToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 |
		uint32(ip4[2])<<8 | uint32(ip4[3])
}

// Uint32ToIP converts a uint32 to a dotted-quad IPv4 string.
func Uint32ToIP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
