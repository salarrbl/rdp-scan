# rdp-scan

Lightweight RDP exposure scanner. Feeds CIDR ranges, finds live TCP/3389
hosts, fingerprints them with an X.224 RDP negotiation handshake, and
emits the results to stdout or a file.

Built for authorized penetration testing and security assessments only.

## Features

- Fast concurrent TCP/3389 scanning with a fixed worker pool
- **RDP fingerprinting**: distinguishes real RDP servers from any other
  service on port 3389 using the X.224 Connection Request, and reports
  the negotiated NLA posture
- Streaming pipeline: memory stays bounded by the number of CIDRs, not
  the number of IPs — a /8 scans with the same footprint as a /24
- Overlapping and adjacent CIDRs are merged, so every address is probed
  exactly once
- Structured output: `txt`, `jsonl`, `csv`, or `targets` (RavenRDP-ready)
- `--only-nla-open` for the recon-to-audit pipeline
- Results on stdout, progress on stderr — safe to pipe and redirect
- Graceful Ctrl+C: partial results are kept, exit code 130
- Single binary, zero external dependencies

## Installation

Build from source with [Go](https://go.dev/):

```bash
git clone https://github.com/salarrbl/rdp-scan.git
cd rdp-scan
make build
```

Or install directly:

```bash
go install ./cmd/rdp-scan
```

The binary is single-file and needs no runtime dependencies.

## Usage

```
rdp-scan <input> [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<input>` | Path to file containing CIDR ranges |

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-o`, `--output` | Output file for results (results go to stdout when omitted) | `stdout` |
| `-c`, `--concurrency` | Number of concurrent probes | `100` |
| `-t`, `--timeout` | Probe timeout, e.g., `500ms`, `2s` | `2s` |
| `--max-cidr` | Skip CIDRs whose prefix is smaller than N. Example: `--max-cidr 24` scans only /24 and smaller. | `0` (no skip) |
| `--format` | Output format: `txt`, `jsonl`, `csv`, `targets` | `txt` |
| `--only-nla-open` | Only report hosts with NLA not enforced | `off` |
| `-h`, `--help` | Show help message | |

### Input File Format

One CIDR per line:

```
# Corporate subnets
1.0.1.0/24
1.0.2.0/23
203.0.113.0/30
```

Lines starting with `#` and blank lines are ignored. Malformed entries
are skipped with a warning on stderr.

### Examples

```bash
# Scan and print IPs to stdout (redirect to a file if you like)
./rdp-scan ranges.txt > live.txt

# Save to a file with more workers
./rdp-scan ranges.txt -o results.txt -c 200

# Emit RavenRDP targets for hosts with NLA not enforced
./rdp-scan ranges.txt --format targets --only-nla-open -o live.txt

# Short timeouts for dead ranges
./rdp-scan ranges.txt -c 50 -t 1s

# Skip anything larger than /24
./rdp-scan ranges.txt --max-cidr 24
```

## RDP fingerprinting

A live TCP port is not necessarily RDP — proxies, VPN concentrators, and
other services sometimes listen on 3389. rdp-scan fingerprints each open
port with the standard RDP negotiation handshake:

1. TCP connect to the address on port 3389.
2. Send the 19-byte X.224 **Connection Request** carrying an
   `RDP_NEG_REQ` (protocol bits `0x00000000`).
3. Read up to 64 bytes of the response with the same deadline.
4. If the reply is an X.224 Disconnect Request carrying an
   `RDP_NEG_RSP`, the selected protocol (little-endian, bytes 15–18 of
   the packet) maps to an NLA posture:

| Protocol bits | NLA value | Meaning |
|---------------|-----------|---------|
| `0x00000000` | `not-enforced` | TLS without NLA — pre-authentication is possible, which is why this is the interesting class for auditing (e.g., with [RavenRDP](https://github.com/0x6c/RavenRDP)) |
| `0x00000002` | `required` | NLA enforced |
| `0x00000008` | `hybrid-ex` | NLA with TLS hybrid |
| anything else | `unknown` | RDP responded, but with an unexpected protocol selection |

If the port is open but the service does not answer with an X.224
response (e.g., a plain HTTP server on 3389), the result is reported
with `rdp=false` and a short `err` reason in structured formats. A
connection that is refused or times out is reported as closed and is not
an error.

## Output

Results are the **only** writes to stdout; every progress, warning, and
error line goes to stderr. Progress on a TTY overwrites a single line
every 250ms (percent, done/total, open count, rate, ETA); off-TTY it
prints one line per 5000 completions.

### `txt` (default)

One IP per line:

```
1.12.34.56
10.0.1.42
```

### `targets`

`host:port` per line, ready for RavenRDP's `targets.txt`:

```
1.12.34.56:3389
10.0.1.42:3389
```

Two-stage pipeline:

```bash
# 1. recon: find RDP hosts with NLA not enforced
./rdp-scan ranges.txt --format targets --only-nla-open -o live.txt
# 2. audit: check those hosts for weak credentials
raven-rdp audit -t live.txt -u users.txt -p pass.txt
```

### `jsonl`

One JSON object per line (stream-safe, `jq`-friendly). `t` is UTC
RFC3339; `err` appears only when the fingerprint failed:

```json
{"ip":"1.12.34.56","port":3389,"rdp":true,"nla":"required","rtt_ms":45,"t":"2026-09-11T13:04:22Z"}
```

### `csv`

Header row plus one row per host:

```
ip,port,rdp,nla,rtt_ms,t
1.12.34.56,3389,true,required,45,2026-09-11T13:04:22Z
```

Results stream as they are discovered (per-record flush), so a running
scan's output file is always up to date — interrupt it (Ctrl+C) and the
hosts found so far remain in the file.

## Concurrency Guidelines

| Target | Recommended `-c` | Notes |
|--------|-----------------|-------|
| /24 (256 hosts) | 50–100 | Default is fine |
| /22 (1k hosts) | 100–200 | ~30s with 2s timeout |
| /20 (4k hosts) | 100–300 | Network-dependent |
| /16 (65k hosts) | 200–500 | Consider `-t 1s` for faster results |

Higher concurrency is faster on fast networks but can saturate a link
or trip rate limits. Lower it if you see many timeouts.

## Performance Tips

1. **Memory is flat**: the pipeline streams the address space; it never
   materializes the full IP list. Peak RSS stays well under 50MB even
   for a /16, and a /12 scans without OOM on a 512MB box.
2. **`--max-cidr`** skips large ranges you do not need.
   `--max-cidr 20` skips /19 and larger networks and still scans /20
   and smaller.
3. **`-t`** matches your network: unroutable space burns the full
   timeout per probe, so use short timeouts for dead ranges.
4. Overlapping CIDRs are merged before scanning, so duplicated input
   costs nothing.

## Error Handling

- Refused or timed-out connections are treated as closed (not an error)
- Malformed CIDR lines are skipped with a warning on stderr
- Read/write failures after connect keep the host `open` with a short
  `fingerprint failed` reason in structured formats
- Output write errors are reported on stderr and set exit code 1
- Exit codes: `0` success, `1` runtime failure, `2` usage error,
  `130` interrupted (Ctrl+C)

## Limitations

- IPv4 only
- TCP/3389 only (no other ports)
- NLA is reported from the initial negotiation; full TLS behavior is
  out of scope
- The fingerprint assumes the service speaks RDP over plain TCP; load
  balancers that terminate RDP may answer differently

## License

GPL-3.0 — see [LICENSE](LICENSE).

## Author

[salarrbl](https://github.com/salarrbl)
