package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"rdp-scan/internal/probe"
)

func sampleResult(err string) probe.Result {
	return probe.Result{
		IP:   "1.12.34.56",
		Port: 3389,
		Open: true,
		RDP:  true,
		NLA:  "required",
		RTT:  45 * time.Millisecond,
		Time: time.Date(2026, 9, 11, 13, 4, 22, 0, time.UTC),
		Err:  err,
	}
}

func TestParseFormat(t *testing.T) {
	for _, f := range []Format{TXT, JSONL, CSV, Targets} {
		if got, ok := ParseFormat(string(f)); !ok || got != f {
			t.Errorf("ParseFormat(%q) = %v, %v; want %v, true", f, got, ok, f)
		}
	}
	for _, bad := range []string{"", "txts", "JSONL", "Targets", "xml"} {
		if _, ok := ParseFormat(bad); ok {
			t.Errorf("ParseFormat(%q) = true, want false", bad)
		}
	}
}

func TestTXT(t *testing.T) {
	var buf bytes.Buffer
	w, err := New(TXT, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(sampleResult("")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "1.12.34.56\n" {
		t.Errorf("txt = %q, want %q", got, "1.12.34.56\n")
	}
}

func TestTargets(t *testing.T) {
	var buf bytes.Buffer
	w, err := New(Targets, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(sampleResult("")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "1.12.34.56:3389\n" {
		t.Errorf("targets = %q, want %q", got, "1.12.34.56:3389\n")
	}
}

func TestJSONL(t *testing.T) {
	var buf bytes.Buffer
	w, err := New(JSONL, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(sampleResult("fingerprint failed: timeout")); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(sampleResult("")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	var rec map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("line 1 not valid JSON: %v", err)
	}
	if rec["ip"] != "1.12.34.56" || rec["port"] != float64(3389) ||
		rec["rdp"] != true || rec["nla"] != "required" || rec["rtt_ms"] != float64(45) {
		t.Errorf("unexpected record: %v", rec)
	}
	if rec["t"] != "2026-09-11T13:04:22Z" {
		t.Errorf("t = %v, want 2026-09-11T13:04:22Z (UTC RFC3339)", rec["t"])
	}
	if rec["err"] != "fingerprint failed: timeout" {
		t.Errorf("err = %v", rec["err"])
	}
	// err is omitted when empty
	var rec2 map[string]interface{}
	if err := json.Unmarshal([]byte(lines[1]), &rec2); err != nil {
		t.Fatal(err)
	}
	if _, present := rec2["err"]; present {
		t.Errorf("err key present on clean record: %v", rec2)
	}
}

func TestCSV(t *testing.T) {
	var buf bytes.Buffer
	w, err := New(CSV, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(sampleResult("")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (header + row)", len(recs))
	}
	wantHeader := []string{"ip", "port", "rdp", "nla", "rtt_ms", "t"}
	for i, wcol := range wantHeader {
		if recs[0][i] != wcol {
			t.Errorf("header[%d] = %q, want %q", i, recs[0][i], wcol)
		}
	}
	wantRow := []string{"1.12.34.56", "3389", "true", "required", "45", "2026-09-11T13:04:22Z"}
	for i, wcol := range wantRow {
		if recs[1][i] != wcol {
			t.Errorf("row[%d] = %q, want %q", i, recs[1][i], wcol)
		}
	}
}

// TestFlushPerRecord verifies records are visible on the underlying
// writer as they are written (streaming), before Close.
func TestFlushPerRecord(t *testing.T) {
	ch := make(chan string, 16)
	w := &teeWriter{ch: ch}
	rw, err := New(TXT, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := rw.Write(sampleResult("")); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-ch:
		if line != "1.12.34.56\n" {
			t.Errorf("streamed line = %q", line)
		}
	default:
		t.Fatal("record not flushed to writer before Close")
	}
}

type teeWriter struct{ ch chan string }

func (t *teeWriter) Write(p []byte) (int, error) {
	select {
	case t.ch <- string(p):
	default:
	}
	return len(p), nil
}
