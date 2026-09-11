package scan

import (
	"fmt"
	"os"
	"time"
)

// isTerminal reports whether f is a TTY (character device).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// renderProgress renders one progress line. It always starts with \r so
// the TTY line is overwritten in place; callers append a newline for
// non-TTY output.
func renderProgress(done, total int64, open int64, elapsed time.Duration) {
	if total <= 0 {
		return
	}
	pct := float64(done) / float64(total) * 100
	var rate float64
	var eta time.Duration
	if elapsed > 0 && done > 0 {
		rate = float64(done) / elapsed.Seconds()
		if done < total {
			eta = time.Duration(float64(total-done)/rate) * time.Second
		}
	}
	fmt.Fprintf(os.Stderr, "\r[*] %.1f%%  %d/%d  open=%d  %.0f/s  ETA %s",
		pct, done, total, open, rate, eta.Round(time.Second))
}
