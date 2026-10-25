package ipintel

import (
	"net/url"
	"testing"
)

func TestSourceCredits(t *testing.T) {
	specs := sourceSpecs(Options{})
	if len(specs) == 0 {
		t.Fatal("no sources")
	}
	seen := make(map[string]bool, len(specs))
	for _, spec := range specs {
		seen[spec.Name] = true
		if spec.Homepage == "" {
			t.Errorf("source %q has no homepage credit", spec.Name)
		}
		if spec.License == "" {
			t.Errorf("source %q has no license", spec.Name)
		}
		if _, err := url.ParseRequestURI(spec.Homepage); err != nil {
			t.Errorf("source %q homepage %q: %v", spec.Name, spec.Homepage, err)
		}
	}
	for name := range sourceHomepages {
		if !seen[name] {
			t.Errorf("homepage credit for unknown source %q", name)
		}
	}
}

func TestSourceParseClosures(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]string{
		"x4b-vpn":         {"1.2.3.0/24"},
		"x4b-datacenter":  {"1.2.4.0/24"},
		"nazgul-vpn":      {"1.2.5.0/24", "2606:4700::/32"},
		"cloudflare-warp": {"1.2.6.0/24"},
		"cloudflare":      {"1.2.7.0/24", "2606:4700::/32"},
	}
	for _, spec := range sourceSpecs(Options{}) {
		body, ok := files[spec.Name]
		if !ok {
			continue
		}
		names := make([]string, 0, len(spec.Files))
		for i, f := range spec.Files {
			writeTestFile(t, dir, f.Name, body[i%len(body)]+"\n")
			names = append(names, f.Name)
		}
		if _, err := spec.Parse(dir, names); err != nil {
			t.Errorf("%s parse: %v", spec.Name, err)
		}
	}
}

func TestParseIPFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "ips.txt", "1.2.3.4\n")
	parse := parseIPFile("tor", 100, map[string]any{"tor_exit": true})
	got, err := parse(dir, []string{"ips.txt"})
	if err != nil || len(got.Records) != 1 || got.Records[0].Category != "tor" {
		t.Fatalf("parseIPFile = %+v, %v", got, err)
	}
}
