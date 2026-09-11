package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rdp-scan/internal/report"
)

func TestParseArgsDefaults(t *testing.T) {
	cfg, err := parseArgs([]string{"in.txt"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.input != "in.txt" || cfg.output != "" || cfg.concurrency != 100 ||
		cfg.timeout != 2*time.Second || cfg.maxCIDR != 0 || cfg.format != report.TXT ||
		cfg.onlyNLAOpen || cfg.help {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestParseArgsAllFlags(t *testing.T) {
	cfg, err := parseArgs([]string{
		"ranges.txt", "-o", "out.txt", "-c", "250", "-t", "500ms",
		"--max-cidr", "20", "--format", "targets", "--only-nla-open",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	want := config{
		input: "ranges.txt", output: "out.txt", concurrency: 250,
		timeout: 500 * time.Millisecond, maxCIDR: 20, format: report.Targets,
		onlyNLAOpen: true,
	}
	if cfg != want {
		t.Errorf("cfg = %+v, want %+v", cfg, want)
	}
}

func TestParseArgsHelp(t *testing.T) {
	cfg, err := parseArgs([]string{"-h"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if !cfg.help {
		t.Error("help = false, want true")
	}
}

func TestParseArgsUsageErrors(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"in.txt", "--concurrancy", "200"}, "unknown flag: --concurrancy"},
		{[]string{"in.txt", "-o"}, "missing value for flag: -o"},
		{[]string{"in.txt", "-c", "abc"}, "invalid concurrency: abc"},
		{[]string{"in.txt", "-c", "0"}, "invalid concurrency: 0"},
		{[]string{"in.txt", "-t", "nope"}, "invalid timeout: nope"},
		{[]string{"in.txt", "--max-cidr", "33"}, "invalid --max-cidr: 33"},
		{[]string{"in.txt", "--max-cidr", "-1"}, "invalid --max-cidr: -1"},
		{[]string{"in.txt", "--format", "xml"}, "unknown format: xml"},
		{[]string{"a.txt", "b.txt"}, "unexpected positional argument: b.txt"},
	}
	for _, tc := range cases {
		_, err := parseArgs(tc.args)
		if err == nil {
			t.Errorf("parseArgs(%v): no error, want %q", tc.args, tc.want)
			continue
		}
		if !strings.HasPrefix(err.Error(), tc.want) {
			t.Errorf("parseArgs(%v) error = %q, want prefix %q", tc.args, err.Error(), tc.want)
		}
	}
}

// TestRunSmoke runs the whole app against an unroutable /32 with a short
// timeout: exit 0, no results, empty report file created.
func TestRunSmoke(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(input, []byte("10.250.250.250/32\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.txt")
	code := run([]string{input, "-o", out, "-t", "50ms", "-c", "4"})
	if code != 0 {
		t.Fatalf("run exit = %d, want 0", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("output = %q, want empty", data)
	}
}

// TestRunEmptyInput verifies the always-create-file behavior: all
// CIDRs filtered by --max-cidr still yields an empty output file.
func TestRunAllFiltered(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(input, []byte("10.0.0.0/8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.txt")
	code := run([]string{input, "-o", out, "--max-cidr", "24", "-t", "50ms"})
	if code != 0 {
		t.Fatalf("run exit = %d, want 0", code)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("empty report file missing: %v", err)
	}
}

func TestRunMissingInputFile(t *testing.T) {
	code := run([]string{"/nonexistent/definitely-missing.txt"})
	if code != 1 {
		t.Fatalf("run exit = %d, want 1", code)
	}
}

func TestRunNoInput(t *testing.T) {
	if code := run([]string{}); code != 1 {
		t.Fatalf("run exit = %d, want 1", code)
	}
}

func TestRunUsageError(t *testing.T) {
	if code := run([]string{"in.txt", "--bogus"}); code != 2 {
		t.Fatalf("run exit = %d, want 2", code)
	}
}
