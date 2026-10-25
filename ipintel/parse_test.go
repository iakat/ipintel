package ipintel

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestParseCIDRText(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "list.txt", "# comment\n1.2.3.0/24\n2001:db8::/32\n9.9.9.9\n")
	got, err := parseCIDRText(dir, []string{"list.txt"}, "vpn", 85, map[string]any{"list": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 3 {
		t.Fatalf("records = %d, want 3", len(got.Records))
	}
	if got.Records[0].Family != 4 || got.Records[0].Category != "vpn" || got.Records[0].Confidence != 85 {
		t.Fatalf("record = %+v", got.Records[0])
	}
	if got.Records[0].Start[0] != 1 || got.Records[0].End[3] != 255 {
		t.Fatalf("ipv4 range = %x/%x", got.Records[0].Start, got.Records[0].End)
	}
	if got.Records[1].Family != 6 {
		t.Fatalf("ipv6 family = %d", got.Records[1].Family)
	}
	if got.Records[2].Family != 4 || got.Records[2].Start != got.Records[2].End {
		t.Fatal("bare IP should become a /32")
	}
}

func TestParsePomerium(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "vpn-pomerium.json", `[{"id":"1.2.3.0/24"},{"id":"2001:db8::/32"}]`)
	got, err := parsePomerium(dir, []string{"vpn-pomerium.json"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 2 || got.Records[0].Category != "vpn_candidate" {
		t.Fatalf("records = %+v", got.Records)
	}
}

func TestParseBadASN(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "bad-asn-list.csv", "ASN,Entity\n15169,\"Google LLC\"\nAS9009,M247\n")
	got, err := parseBadASN(dir, []string{"bad-asn-list.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ASNs) != 2 || got.ASNs[15169] != "Google LLC" || got.ASNs[9009] != "M247" {
		t.Fatalf("asns = %+v", got.ASNs)
	}
}

func TestParseOpenProxies(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "open-proxies.txt", "http://1.2.3.4:8080\nsocks5://[2001:db8::1]:1080\nuser:pass@5.6.7.8:3128\n")
	got, err := parseOpenProxies(dir, []string{"open-proxies.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 3 {
		t.Fatalf("records = %d", len(got.Records))
	}
	if got.Records[0].Category != "proxy" || got.Records[1].Family != 6 {
		t.Fatalf("records = %+v", got.Records)
	}
}

func TestParseICloudRelay(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "icloud-relay.csv", "1.2.3.0/24,DE,DE-BE,Berlin,\n2001:db8::/32,US,US-CA,San Francisco,\n")
	got, err := parseICloudRelay(dir, []string{"icloud-relay.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 2 || got.Records[0].Category != "relay" || got.Records[0].Country != "DE" {
		t.Fatalf("records = %+v", got.Records)
	}
}

func TestParseAWSSmall(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "aws.json", `{
		"prefixes":[{"ip_prefix":"1.2.3.0/24","region":"eu-west-1","service":"AMAZON"}],
		"ipv6_prefixes":[{"ipv6_prefix":"2001:db8::/32","region":"eu-west-1","service":"AMAZON"}]
	}`)
	got, err := parseAWS(dir, []string{"aws.json"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 2 || got.Records[0].Category != "hosting" || got.Records[1].Family != 6 {
		t.Fatalf("records = %+v", got.Records)
	}
}
