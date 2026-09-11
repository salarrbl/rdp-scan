package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"rdp-scan/internal/report"
)

// config holds the validated CLI configuration.
type config struct {
	input       string
	output      string // empty = stdout
	concurrency int
	timeout     time.Duration
	maxCIDR     int
	format      report.Format
	onlyNLAOpen bool
	help        bool
}

// parseArgs parses CLI arguments. It returns a usage error for unknown
// flags, missing flag values, invalid values, and extra positional
// arguments (the caller reports it and exits 2). An empty input is not
// an error here; the caller reports it with usage and exits 1.
func parseArgs(args []string) (cfg config, err error) {
	cfg = config{concurrency: 100, timeout: 2 * time.Second, format: report.TXT}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		// need reads the value following arg, or reports a missing value
		need := func() string {
			if i+1 >= len(args) {
				err = fmt.Errorf("missing value for flag: %s", arg)
				return ""
			}
			i++
			return args[i]
		}
		switch arg {
		case "-o", "--output":
			cfg.output = need()
		case "-c", "--concurrency":
			v := need()
			if n, aerr := strconv.Atoi(v); aerr != nil || n <= 0 {
				err = fmt.Errorf("invalid concurrency: %s (must be a positive integer)", v)
			} else {
				cfg.concurrency = n
			}
		case "-t", "--timeout":
			v := need()
			if d, aerr := time.ParseDuration(v); aerr != nil || d <= 0 {
				err = fmt.Errorf("invalid timeout: %s (e.g., 500ms, 2s)", v)
			} else {
				cfg.timeout = d
			}
		case "--max-cidr":
			v := need()
			if n, aerr := strconv.Atoi(v); aerr != nil || n < 0 || n > 32 {
				err = fmt.Errorf("invalid --max-cidr: %s (must be 0-32)", v)
			} else {
				cfg.maxCIDR = n
			}
		case "--format":
			v := need()
			if f, valid := report.ParseFormat(v); !valid {
				err = fmt.Errorf("unknown format: %s (valid: txt, jsonl, csv, targets)", v)
			} else {
				cfg.format = f
			}
		case "--only-nla-open":
			cfg.onlyNLAOpen = true
		case "-h", "--help":
			cfg.help = true
			return cfg, nil
		default:
			if len(arg) > 0 && arg[0] == '-' {
				err = fmt.Errorf("unknown flag: %s", arg)
			} else if cfg.input == "" {
				cfg.input = arg
			} else {
				err = fmt.Errorf("unexpected positional argument: %s", arg)
			}
		}
		if err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

// printUsage prints the help text to stderr.
func printUsage() {
	fmt.Fprintf(os.Stderr, `rdp-scan - Lightweight RDP exposure scanner

Usage: rdp-scan <input> [options]

Arguments:
  <input>           Path to file containing CIDR ranges

Options:
  -o, --output      Output file for results (default: stdout)
  -c, --concurrency Number of concurrent probes (default: 100)
  -t, --timeout     Probe timeout (default: 2s, e.g., 500ms, 2s)
  --max-cidr        Skip CIDRs whose prefix is smaller than N.
                    Example: --max-cidr 24 scans only /24 and smaller.
  --format          Output format: txt, jsonl, csv, targets (default: txt)
  --only-nla-open   Only report hosts with NLA not enforced
  -h, --help        Show this help message

Input file format:
  One CIDR per line, e.g.:
    1.0.1.0/24
    1.0.2.0/23

  Lines starting with # are comments.
  Blank lines are ignored.
  Malformed entries are skipped with a warning.

Examples:
  rdp-scan ranges.txt
  rdp-scan ranges.txt -o results.txt -c 200
  rdp-scan ranges.txt --format targets -o live.txt
  rdp-scan ranges.txt --format targets --only-nla-open -o live.txt
  rdp-scan ranges.txt -c 50 -t 1s
  rdp-scan ranges.txt --max-cidr 24
`)
}
