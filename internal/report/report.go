// Package report writes scan results in the selected format. Writers
// flush per record so results stream out as they are discovered.
package report

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"rdp-scan/internal/probe"
)

// Format selects the output format (B3).
type Format string

// Supported output formats.
const (
	TXT     Format = "txt"     // one IP per line
	JSONL   Format = "jsonl"   // one JSON object per line
	CSV     Format = "csv"     // header row ip,port,rdp,nla,rtt_ms,t
	Targets Format = "targets" // "host:port" per line, consumed by RavenRDP
)

// ParseFormat validates a --format value.
func ParseFormat(s string) (Format, bool) {
	switch Format(s) {
	case TXT, JSONL, CSV, Targets:
		return Format(s), true
	}
	return "", false
}

// Writer streams one formatted record per host. Write is called
// sequentially by the single reporter goroutine; no locking is needed.
type Writer interface {
	Write(res probe.Result) error
	Close() error
}

type buffered struct{ w *bufio.Writer }

func (b *buffered) flush() error { return b.w.Flush() }
func (b *buffered) Close() error { return b.w.Flush() }

type txtWriter struct{ *buffered }

func (t *txtWriter) Write(r probe.Result) error {
	if _, err := fmt.Fprintln(t.w, r.IP); err != nil {
		return err
	}
	return t.flush()
}

type targetsWriter struct{ *buffered }

func (t *targetsWriter) Write(r probe.Result) error {
	if _, err := fmt.Fprintf(t.w, "%s:%d\n", r.IP, r.Port); err != nil {
		return err
	}
	return t.flush()
}

type jsonlWriter struct{ *buffered }

type jsonlRecord struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	RDP  bool   `json:"rdp"`
	NLA  string `json:"nla"`
	RTT  int64  `json:"rtt_ms"`
	T    string `json:"t"`
	Err  string `json:"err,omitempty"`
}

func (j *jsonlWriter) Write(r probe.Result) error {
	rec := jsonlRecord{
		IP:   r.IP,
		Port: r.Port,
		RDP:  r.RDP,
		NLA:  r.NLA,
		RTT:  int64(r.RTT / time.Millisecond),
		T:    r.Time.UTC().Format(time.RFC3339),
		Err:  r.Err,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := j.w.Write(append(data, '\n')); err != nil {
		return err
	}
	return j.flush()
}

type csvWriter struct {
	*buffered
	cw *csv.Writer
}

func (c *csvWriter) Write(r probe.Result) error {
	err := c.cw.Write([]string{
		r.IP,
		strconv.Itoa(r.Port),
		strconv.FormatBool(r.RDP),
		r.NLA,
		strconv.FormatInt(int64(r.RTT/time.Millisecond), 10),
		r.Time.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	c.cw.Flush()
	if err := c.cw.Error(); err != nil {
		return err
	}
	return c.flush()
}

// New builds the writer for the selected format. CSV gets a header row;
// all writers flush per record.
func New(f Format, out io.Writer) (Writer, error) {
	buf := bufio.NewWriter(out)
	switch f {
	case TXT:
		return &txtWriter{&buffered{buf}}, nil
	case Targets:
		return &targetsWriter{&buffered{buf}}, nil
	case JSONL:
		return &jsonlWriter{&buffered{buf}}, nil
	case CSV:
		cw := csv.NewWriter(buf)
		if err := cw.Write([]string{"ip", "port", "rdp", "nla", "rtt_ms", "t"}); err != nil {
			return nil, err
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			return nil, err
		}
		return &csvWriter{&buffered{buf}, cw}, nil
	}
	return nil, fmt.Errorf("unknown output format: %s", f)
}
