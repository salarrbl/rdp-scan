# RDP Exposure Scanner

Lightweight CLI tool for authorized corporate penetration testing. Discovers live RDP (TCP/3389) hosts from CIDR ranges.

## Features

- CIDR range expansion with deduplication and overlap handling
- RDP validation on TCP/3389: sends an X.224 Connection Request and requires a
  Connection Confirm back, instead of trusting a bare TCP connect
  (no nmap, no UDP, no brute force)
- Non-RDP services listening on 3389 are reported separately, not counted as RDP
- Bounded concurrency with configurable worker pool
- Configurable timeout for both the connect and the handshake
- Progress tracking
- Graceful handling of malformed input; IPv6 ranges reported as unsupported
- Single binary, zero external dependencies

## Installation

```bash
go build -o rdp-scan main.go
```

Or with Go modules:

```bash
go mod init rdp-scan
go mod tidy
go build -o rdp-scan .
```

## Usage

```bash
./rdp-scan <input> [options]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `<input>` | Path to file containing CIDR ranges | Required |
| `-o, --output` | Output file for found hosts | `rdp_live.txt` |
| `-c, --concurrency` | Number of concurrent TCP checks | `100` |
| `-t, --timeout` | Per-host timeout for the TCP connect **and** the RDP handshake that follows it (e.g., `500ms`, `2s`) | `5s` |
| `--max-cidr` | Skip CIDRs smaller than this prefix (e.g., `20` skips /20 and larger networks) | `0` (no skip) |

### Input File Format

One CIDR per line:

```text
1.0.1.0/24
1.0.2.0/23
# This is a comment
1.0.8.0/21

1.0.32.0/19
```

Blank lines and lines starting with `#` are ignored (a `#` only starts a comment
at the beginning of a line - do not put trailing comments after a CIDR).
Malformed entries are skipped with a warning that says what is wrong with them;
valid IPv6 ranges are skipped as unsupported rather than being called malformed.
Host bits are masked off, so `10.0.0.5/24` expands `10.0.0.0/24`.

## Examples

### Basic scan

```bash
./rdp-scan ranges.txt
```

### With custom output and concurrency

```bash
./rdp-scan ranges.txt -o results.txt -c 200
```

### Quick scan with lower concurrency

```bash
./rdp-scan ranges.txt -c 50 -t 1s
```

### Skip large ranges (only scan /24 and smaller)

```bash
./rdp-scan ranges.txt --max-cidr 24
```

### Large-scale scan with conservative resources

```bash
./rdp-scan cn-i-ranges.txt -c 100 -t 2s --max-cidr 20
```

## Concurrency Guidelines

Choose concurrency based on your available resources:

| CPU Cores | Suggested Concurrency | Notes |
|-----------|----------------------|-------|
| 2 | 50-100 | Low impact |
| 4 | 100-200 | Balanced |
| 8 | 200-500 | Aggressive |
| 16+ | 500-1000 | Maximum throughput |

**Start conservative.** If you see high CPU/memory usage, reduce `--concurrency`. A good rule of thumb: start with `concurrency = cores * 25` and adjust up or down based on system response.

## Performance Tips

1. **Use `--max-cidr`** to skip large ranges that would take too long. For example, `--max-cidr 20` skips /20, /19, /16, etc.
2. **Lower concurrency** on slower networks or shared machines.
3. **Shorter timeout** (`-t 500ms`) for faster scans when you expect most hosts to be unreachable.
4. **Longer timeout** (`-t 5s`) for networks with higher latency.

## Output

Confirmed RDP hosts are printed to stdout as they're discovered:

```text
[+] 1.0.1.14:3389 OPEN
[+] 1.0.1.72:3389 OPEN
```

Hosts that accept the TCP connection on 3389 but do not complete the RDP
handshake are reported separately, with the reason, and are **not** written to
the output file:

```text
[!] 1.0.1.90:3389 open, no RDP handshake (not a TPKT response (first byte 0x53))
[!] 1.0.1.91:3389 open, no RDP handshake (handshake: timeout waiting for RDP handshake)
[!] 1.0.1.92:3389 open, no RDP handshake (handshake: closed without a response)
...
[+] 2 RDP host(s) found
[!] 3 host(s) with 3389/tcp open that did not speak RDP
```

Results are saved to the output file:

```text
1.0.1.14
1.0.1.72
```

## How It Works

1. **Parse** CIDR ranges from input file (skipping comments, blanks, malformed and IPv6 entries)
2. **Expand** ranges to individual IPs, deduplicating across overlapping ranges
3. **Skip** ranges larger than `--max-cidr` prefix (to prevent memory/CPU overload)
4. **Probe** each IP on TCP/3389: connect, then send an RDP X.224 Connection
   Request PDU (MS-RDPBCGR 2.2.1.1) with an RDP Negotiation Request for
   TLS|CredSSP, all within the `-t` timeout
5. **Validate** the reply: it must be a TPKT packet (RFC 1006) carrying an X.224
   Connection Confirm TPDU (`0xD0`). An RDP Negotiation Response (`0x02`) or
   Negotiation Failure (`0x03`) inside it still counts as RDP
6. **Report** hosts that completed the handshake as `OPEN`; hosts whose port is
   open but which answer with a foreign banner, nothing at all, or an immediate
   close are reported as `open, no RDP handshake`
7. **Save** the confirmed RDP hosts to the output file

## Error Handling

- Malformed CIDRs are logged with the reason (bad address, missing prefix,
  prefix out of the IPv4 0-32 range) and skipped
- IPv6 CIDRs are logged as unsupported - not as malformed - and skipped
- Overlapping CIDRs are deduplicated
- Large CIDRs (configurable via `--max-cidr`) are skipped with a warning
- Timeouts don't hang the scan: `-t` bounds the connect *and* the handshake, and
  a deadline miss is detected with `errors.As`/`net.Error.Timeout()` because
  `net.Conn` wraps it in a `*net.OpError`
- Refused connections are treated as closed (not errors)

## Limitations

- IPv4 only
- TCP/3389 only (no other ports)
- No authentication or credential testing
- No service enumeration beyond the RDP handshake
- A middlebox (firewall, IPS, TCP load balancer) that completes the TCP
  handshake but swallows the Connection Request will be reported as
  `open, no RDP handshake` rather than as an RDP host

## Testing

```bash
make build        # compile ./rdp-scan
go test ./...     # unit tests + handshake tests against in-process fake listeners
make check        # go vet
make test-sample  # scan test-ranges.txt
make test-local   # scan test-local.txt (loopback)
```

`go test` covers CIDR parsing/expansion, the X.224 Connection Request bytes,
Connection Confirm validation, and `probeRDP` against fake listeners that
behave like RDP, SSH, HTTP, a silent socket, a half-sent packet and an
immediate close. `test-ranges.txt` and `test-local.txt` contain only loopback
(RFC 1122) and documentation (RFC 5737) space, so `make test-sample` never
touches a third-party host.


## License

GPL-3.0

## Author

For authorized penetration testing use only. Ensure you have explicit written permission before scanning any networks.
# rdp-scan
