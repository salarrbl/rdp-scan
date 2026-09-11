package scan

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"rdp-scan/internal/cidr"
	"rdp-scan/internal/probe"
)

// recordingProbe records every probed address (deduplicated) and marks
// the given open set as open.
type recordingProbe struct {
	mu       sync.Mutex
	seen     map[string]int
	openSet  map[string]bool
	maxIn    atomic.Int64
	inFlight atomic.Int64
	sleep    time.Duration
}

func newRecordingProbe(open []string, sleep time.Duration) *recordingProbe {
	rp := &recordingProbe{seen: map[string]int{}, openSet: map[string]bool{}, sleep: sleep}
	for _, ip := range open {
		rp.openSet[ip] = true
	}
	return rp
}

func (rp *recordingProbe) fn(ctx context.Context, ip string, port int, timeout time.Duration) probe.Result {
	rp.inFlight.Add(1)
	for {
		cur := rp.maxIn.Load()
		if cur >= rp.inFlight.Load() || rp.maxIn.CompareAndSwap(cur, rp.inFlight.Load()) {
			break
		}
	}
	defer rp.inFlight.Add(-1)
	if rp.sleep > 0 {
		time.Sleep(rp.sleep)
	}
	rp.mu.Lock()
	rp.seen[ip]++
	rp.mu.Unlock()
	res := probe.Result{IP: ip, Port: port}
	if rp.openSet[ip] {
		res.Open = true
		res.RDP = true
		res.NLA = "required"
	}
	return res
}

func (rp *recordingProbe) snapshot() map[string]int {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	out := make(map[string]int, len(rp.seen))
	for k, v := range rp.seen {
		out[k] = v
	}
	return out
}

func ipRange(t *testing.T, start string, count int) cidr.Range {
	t.Helper()
	s := cidr.IPToUint32(net.ParseIP(start))
	return cidr.Range{Start: s, End: s + uint32(count) - 1}
}

func TestRunCoversEveryAddressExactlyOnce(t *testing.T) {
	ranges := []cidr.Range{
		ipRange(t, "10.0.0.0", 8), // 10.0.0.0/29
		ipRange(t, "10.0.1.0", 4), // 10.0.1.0/30
		ipRange(t, "192.168.5.9", 1),
	}
	rp := newRecordingProbe([]string{"10.0.0.3", "192.168.5.9"}, 0)
	var mu sync.Mutex
	var got []probe.Result
	err := run(context.Background(), ranges, 5, time.Second, rp.fn, func(r probe.Result) {
		mu.Lock()
		got = append(got, r)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(got) != 13 {
		t.Fatalf("got %d results, want 13", len(got))
	}
	seen := rp.snapshot()
	if len(seen) != 13 {
		t.Fatalf("probe saw %d unique addresses, want 13: %v", len(seen), seen)
	}
	for ip, n := range seen {
		if n != 1 {
			t.Errorf("address %s probed %d times, want 1", ip, n)
		}
	}
	// spot-check expected addresses exist
	for _, want := range []string{"10.0.0.0", "10.0.0.7", "10.0.1.0", "10.0.1.3", "192.168.5.9"} {
		if seen[want] != 1 {
			t.Errorf("missing or repeated address %s: %v", want, seen[want])
		}
	}
	open := 0
	for _, r := range got {
		if r.Open {
			open++
		}
	}
	if open != 2 {
		t.Errorf("open = %d, want 2", open)
	}
}

func TestRunRespectsConcurrencyBound(t *testing.T) {
	ranges := []cidr.Range{ipRange(t, "10.1.0.0", 400)}
	rp := newRecordingProbe(nil, 2*time.Millisecond)
	err := run(context.Background(), ranges, 8, time.Second, rp.fn, func(probe.Result) {})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if mx := rp.maxIn.Load(); mx > 8 {
		t.Errorf("max in-flight = %d, want <= 8", mx)
	}
}

func TestRunZeroRanges(t *testing.T) {
	called := false
	err := run(context.Background(), nil, 4, time.Second, probe.Probe, func(probe.Result) { called = true })
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if called {
		t.Error("emit called with zero ranges")
	}
}

func TestRunCancelledContext(t *testing.T) {
	ranges := []cidr.Range{ipRange(t, "10.2.0.0", 1000)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	var n int64
	err := run(ctx, ranges, 4, 50*time.Millisecond, probe.Probe, func(probe.Result) { n++ })
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("cancelled run took %v, want fast drain", time.Since(start))
	}
	// With a pre-cancelled context no probe can open a connection.
	if n > 0 {
		t.Logf("note: %d results emitted after pre-cancel (all closed)", n)
	}
}
