// Command rdp-scan discovers live RDP (TCP/3389) endpoints from CIDR
// ranges and fingerprints each open port with an X.224 RDP negotiation
// handshake. Results stream to stdout (or the -o file); all progress
// and status output goes to stderr.
//
// It is intended for authorized penetration testing only.
package main

import (
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}
