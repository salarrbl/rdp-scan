package cidr

import (
	"net"
	"os"
	"strings"
	"testing"
)

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func sameCIDR(a, b CIDR) bool {
	return a.Mask == b.Mask && a.IP.Equal(b.IP)
}

func TestParseCIDR(t *testing.T) {
	valid := map[string]CIDR{
		"1.2.3.4/24":         {net.IPv4(1, 2, 3, 4), 24},
		"10.0.0.0/8":         {net.IPv4(10, 0, 0, 0), 8},
		"10.0.0.5/24":        {net.IPv4(10, 0, 0, 5), 24},
		"0.0.0.0/0":          {net.IPv4(0, 0, 0, 0), 0},
		"255.255.255.255/32": {net.IPv4(255, 255, 255, 255), 32},
		" 192.168.1.0/30 ":   {net.IPv4(192, 168, 1, 0), 30},
	}
	for in, want := range valid {
		got, ok := ParseCIDR(in)
		if !ok {
			t.Errorf("ParseCIDR(%q) = false, want true", in)
			continue
		}
		if !sameCIDR(got, want) {
			t.Errorf("ParseCIDR(%q) = %+v, want %+v", in, got, want)
		}
	}

	invalid := []string{
		"",
		"1.2.3.4",       // no prefix
		"1.2.3.4/33",    // prefix too large
		"1.2.3.4/-1",    // negative prefix
		"1.2.3.4/abc",   // non-numeric prefix
		"999.2.3.4/24",  // bad octet
		"1.2.3/24",      // too few octets
		"2001:db8::/32", // IPv6
		"1.2.3.4/24/8",  // extra slash
		"host/24",       // unparseable IP
	}
	for _, in := range invalid {
		if _, ok := ParseCIDR(in); ok {
			t.Errorf("ParseCIDR(%q) = true, want false", in)
		}
	}
}

func TestReadCIDRs(t *testing.T) {
	content := `# comment line
10.0.1.0/24

10.0.2.0/23
bogus-line
10.0.9.0/33
# another comment
192.168.0.0/16
`
	f := t.TempDir() + "/in.txt"
	if err := writeFile(f, content); err != nil {
		t.Fatal(err)
	}

	var warn strings.Builder
	cidrs, err := ReadCIDRs(f, 0, &warn)
	if err != nil {
		t.Fatalf("ReadCIDRs: %v", err)
	}
	if len(cidrs) != 3 {
		t.Fatalf("got %d CIDRs, want 3: %+v", len(cidrs), cidrs)
	}
	want := []CIDR{
		{net.IPv4(10, 0, 1, 0), 24},
		{net.IPv4(10, 0, 2, 0), 23},
		{net.IPv4(192, 168, 0, 0), 16},
	}
	for i, w := range want {
		if !sameCIDR(cidrs[i], w) {
			t.Errorf("cidrs[%d] = %+v, want %+v", i, cidrs[i], w)
		}
	}
	if !strings.Contains(warn.String(), "Skipping malformed CIDR: bogus-line") {
		t.Errorf("warnings missing malformed note: %q", warn.String())
	}
	if !strings.Contains(warn.String(), "Skipping malformed CIDR: 10.0.9.0/33") {
		t.Errorf("warnings missing /33 note: %q", warn.String())
	}

	// maxCIDR=24 keeps /24 and smaller, skips /23 and /16
	warn.Reset()
	cidrs, err = ReadCIDRs(f, 24, &warn)
	if err != nil {
		t.Fatalf("ReadCIDRs(maxCIDR): %v", err)
	}
	if len(cidrs) != 1 || !sameCIDR(cidrs[0], CIDR{net.IPv4(10, 0, 1, 0), 24}) {
		t.Fatalf("maxCIDR=24: got %+v, want only 10.0.1.0/24", cidrs)
	}
	if !strings.Contains(warn.String(), "Skipping 10.0.2.0/23") {
		t.Errorf("maxCIDR warnings missing /23 skip: %q", warn.String())
	}
	if !strings.Contains(warn.String(), "Skipping 192.168.0.0/16") {
		t.Errorf("maxCIDR warnings missing /16 skip: %q", warn.String())
	}
}

func TestReadCIDRsMissingFile(t *testing.T) {
	if _, err := ReadCIDRs("/nonexistent/nope.txt", 0, nil); err == nil {
		t.Fatal("expected error for missing file")
	}
}
