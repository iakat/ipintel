package ipintel

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

type fakeNetworkCall struct {
	network *net.IPNet
	err     error
}

type fakeNetworks struct {
	calls []fakeNetworkCall
	i     int
	err   error
}

func (f *fakeNetworks) Next() bool { return f.i < len(f.calls) }
func (f *fakeNetworks) Network(any) (*net.IPNet, error) {
	c := f.calls[f.i]
	f.i++
	return c.network, c.err
}
func (f *fakeNetworks) Err() error { return f.err }

func writeTestMMDB(t *testing.T, dir, name string, records map[string]mmdbtype.Map) string {
	t.Helper()
	writer, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "Test",
		RecordSize:   24,
		IPVersion:    6,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(records))
	for cidr := range records {
		keys = append(keys, cidr)
	}
	sort.Strings(keys)
	for _, cidr := range keys {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Insert(network, records[cidr]); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteTo(f); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParsePrefix(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"1.2.3.4", "1.2.3.4/32", false},
		{"1.2.3.4/24", "1.2.3.0/24", false},
		{"2001:db8::1", "2001:db8::1/128", false},
		{"::ffff:1.2.3.4", "1.2.3.4/32", false},
		{"", "", true},
		{"not-an-ip", "", true},
		{"1.2.3.4/99", "", true},
	}
	for _, tc := range tests {
		got, err := parsePrefix(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parsePrefix(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil || got.String() != tc.want {
			t.Errorf("parsePrefix(%q) = %v, %v; want %s", tc.in, got, err, tc.want)
		}
	}
}

func TestRecordFromPrefixInvalid(t *testing.T) {
	rec := recordFromPrefix(netip.Prefix{}, "test", 1, "{}")
	if rec.Family != 0 {
		t.Fatalf("invalid prefix family = %d, want 0", rec.Family)
	}
}

func TestParseCIDRTextErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := parseCIDRText(dir, []string{"missing.txt"}, "vpn", 1, nil); err == nil {
		t.Fatal("missing file should fail")
	}
	writeTestFile(t, dir, "bad.txt", "1.2.3.4/99\n")
	if _, err := parseCIDRText(dir, []string{"bad.txt"}, "vpn", 1, nil); err == nil {
		t.Fatal("invalid CIDR should fail")
	}
	writeTestFile(t, dir, "long.txt", strings.Repeat("1", 2*1024*1024+1))
	if _, err := parseCIDRText(dir, []string{"long.txt"}, "vpn", 1, nil); err == nil {
		t.Fatal("scanner error should fail")
	}
}

func TestParseProviderIPs(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "vpn-provider-mullvad.txt", "1.2.3.0/24\n")
	got, err := parseProviderIPs(dir, []string{"vpn-provider-mullvad.txt"})
	if err != nil || len(got.Records) != 1 {
		t.Fatalf("provider parse = %+v, %v", got, err)
	}
	if !strings.Contains(got.Records[0].Detail, `"provider":"mullvad"`) {
		t.Fatalf("provider detail = %s", got.Records[0].Detail)
	}
	if _, err := parseProviderIPs(dir, []string{"missing.txt"}); err == nil {
		t.Fatal("missing provider file should fail")
	}
}

func TestParsePomeriumErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := parsePomerium(dir, []string{"missing.json"}); err == nil {
		t.Fatal("missing pomerium file should fail")
	}
	writeTestFile(t, dir, "bad.json", "{")
	if _, err := parsePomerium(dir, []string{"bad.json"}); err == nil {
		t.Fatal("bad pomerium JSON should fail")
	}
	writeTestFile(t, dir, "badcidr.json", `[{"id":"not-a-cidr"}]`)
	if _, err := parsePomerium(dir, []string{"badcidr.json"}); err == nil {
		t.Fatal("bad pomerium CIDR should fail")
	}
}

func TestParseBadASNErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := parseBadASN(dir, []string{"missing.csv"}); err == nil {
		t.Fatal("missing bad-asn file should fail")
	}
	writeTestFile(t, dir, "bad.csv", "\"unterminated\n")
	if _, err := parseBadASN(dir, []string{"bad.csv"}); err == nil {
		t.Fatal("bad CSV should fail")
	}
	writeTestFile(t, dir, "rows.csv", "ASN,Entity\nnot-an-asn,Ignored\nAS123, \nAS456,Kept\n")
	got, err := parseBadASN(dir, []string{"rows.csv"})
	if err != nil || len(got.ASNs) != 1 || got.ASNs[456] != "Kept" {
		t.Fatalf("bad ASN rows = %+v, %v", got.ASNs, err)
	}
}

func TestParseOpenASNSuccess(t *testing.T) {
	dir := t.TempDir()
	writeTestMMDB(t, dir, "openasn.mmdb", map[string]mmdbtype.Map{
		"1.2.3.0/24": {
			"asn":            mmdbtype.Uint32(64500),
			"as_org":         mmdbtype.String("Test Org"),
			"category":       mmdbtype.String("hosting"),
			"network_role":   mmdbtype.String("datacenter"),
			"bad_asn":        mmdbtype.Bool(true),
			"vpn_provider":   mmdbtype.Bool(true),
			"mobile_carrier": mmdbtype.Bool(true),
			"enterprise_gw":  mmdbtype.Bool(true),
			"cdn":            mmdbtype.Bool(true),
			"hosting_extra":  mmdbtype.Bool(true),
			"vpn_range":      mmdbtype.Bool(true),
			"core_verdict":   mmdbtype.String("vpn"),
			"core_sources":   mmdbtype.Slice{mmdbtype.String("x4b_vpn")},
		},
		"8.8.8.0/24": {
			"core_sources": mmdbtype.Slice{mmdbtype.String("other")},
		},
	})
	got, err := parseOpenASN(dir, []string{"openasn.mmdb"})
	if err != nil || len(got.Records) != 2 {
		t.Fatalf("openasn parse = %d records, %v", len(got.Records), err)
	}
	if got.Records[0].ASN != 64500 || got.Records[0].Org != "Test Org" || got.Records[0].Category != "vpn" {
		t.Fatalf("openasn record = %+v", got.Records[0])
	}
	if got.Records[1].Category != "unknown" {
		t.Fatalf("empty verdict category = %q", got.Records[1].Category)
	}
}

func TestParseOpenASNErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := parseOpenASN(dir, []string{"missing.mmdb"}); err == nil {
		t.Fatal("missing openasn db should fail")
	}
	networkErr := &fakeNetworks{calls: []fakeNetworkCall{{err: os.ErrInvalid}}}
	if _, err := parseOpenASNNetworks(networkErr); err == nil {
		t.Fatal("network error should fail")
	}
	badPrefix := &fakeNetworks{calls: []fakeNetworkCall{{network: &net.IPNet{}}}}
	if _, err := parseOpenASNNetworks(badPrefix); err == nil {
		t.Fatal("bad network prefix should fail")
	}
	finalErr := &fakeNetworks{err: os.ErrInvalid}
	if _, err := parseOpenASNNetworks(finalErr); err == nil {
		t.Fatal("final network error should fail")
	}
}

func TestOpenASNConfidence(t *testing.T) {
	tests := []struct {
		verdict string
		sources []string
		want    uint8
	}{
		{"vpn", []string{"x4b_vpn"}, 85},
		{"vpn", []string{"asn_vpn_provider"}, 80},
		{"vpn", nil, 75},
		{"hosting", []string{"x4b_dc"}, 80},
		{"hosting", []string{"asn_hosting_extra"}, 75},
		{"hosting", []string{"asn_bad_asn"}, 60},
		{"hosting", []string{"asn_cdn"}, 50},
		{"hosting", []string{"asn_category"}, 55},
		{"hosting", nil, 70},
		{"mobile", nil, 80},
		{"residential_isp", nil, 60},
		{"business", nil, 50},
		{"education", nil, 50},
		{"government", nil, 50},
		{"other", nil, 0},
	}
	for _, tc := range tests {
		if got := openASNConfidence(tc.verdict, tc.sources); got != tc.want {
			t.Errorf("openASNConfidence(%q, %v) = %d, want %d", tc.verdict, tc.sources, got, tc.want)
		}
	}
}

func TestParseGeoLiteSuccess(t *testing.T) {
	dir := t.TempDir()
	writeTestMMDB(t, dir, "country.mmdb", map[string]mmdbtype.Map{
		"1.2.3.0/24":     {"country": mmdbtype.Map{"iso_code": mmdbtype.String("de")}},
		"2606:4700::/32": {"country": mmdbtype.Map{"iso_code": mmdbtype.String("us")}},
	})
	country, err := parseGeoLiteCountry(dir, []string{"country.mmdb"})
	if err != nil || len(country.Records) != 2 || country.Records[0].Country != "DE" {
		t.Fatalf("country parse = %+v, %v", country, err)
	}
	writeTestMMDB(t, dir, "asn.mmdb", map[string]mmdbtype.Map{
		"8.8.8.0/24": {
			"autonomous_system_number":       mmdbtype.Uint32(64501),
			"autonomous_system_organization": mmdbtype.String("ASN Org"),
		},
	})
	asn, err := parseGeoLiteASN(dir, []string{"asn.mmdb"})
	if err != nil || len(asn.Records) != 1 || asn.Records[0].ASN != 64501 || asn.Records[0].Org != "ASN Org" {
		t.Fatalf("asn parse = %+v, %v", asn, err)
	}
}

func TestParseGeoLiteErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := parseGeoLiteCountry(dir, []string{"missing.mmdb"}); err == nil {
		t.Fatal("missing country db should fail")
	}
	if _, err := parseGeoLiteASN(dir, []string{"missing.mmdb"}); err == nil {
		t.Fatal("missing asn db should fail")
	}
	for _, parse := range []func(networksReader) (parsedSource, error){
		parseGeoLiteCountryNetworks, parseGeoLiteASNNetworks,
	} {
		if _, err := parse(&fakeNetworks{calls: []fakeNetworkCall{{err: os.ErrInvalid}}}); err == nil {
			t.Fatal("network error should fail")
		}
		if _, err := parse(&fakeNetworks{calls: []fakeNetworkCall{{network: &net.IPNet{}}}}); err == nil {
			t.Fatal("bad network prefix should fail")
		}
		if _, err := parse(&fakeNetworks{err: os.ErrInvalid}); err == nil {
			t.Fatal("final network error should fail")
		}
	}
}

func TestParseICloudRelayErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := parseICloudRelay(dir, []string{"missing.csv"}); err == nil {
		t.Fatal("missing icloud file should fail")
	}
	if _, err := parseICloudRelay(dir, []string{"."}); err == nil {
		t.Fatal("directory icloud input should fail")
	}
	writeTestFile(t, dir, "short.csv", "not-a-cidr\nde\n1.2.3.0/24\n1.2.4.0/24,DE\n1.2.5.0/24,FR,IDF\n1.2.6.0/24,US,CA,SF\n")
	got, err := parseICloudRelay(dir, []string{"short.csv"})
	if err != nil || len(got.Records) != 4 {
		t.Fatalf("icloud rows = %+v, %v", got.Records, err)
	}
}

func TestParseOpenProxiesErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := parseOpenProxies(dir, []string{"missing.txt"}); err == nil {
		t.Fatal("missing proxy file should fail")
	}
	writeTestFile(t, dir, "long.txt", strings.Repeat("x", 1024*1024+1))
	if _, err := parseOpenProxies(dir, []string{"long.txt"}); err == nil {
		t.Fatal("long proxy line should fail")
	}
	writeTestFile(t, dir, "bad.txt", "# comment\nhttp://[::1\nhttp:///missing-host\nhttp://999.999.999.999:1\nhttp://1.2.3.4\n")
	got, err := parseOpenProxies(dir, []string{"bad.txt"})
	if err != nil || len(got.Records) != 1 {
		t.Fatalf("bad proxies = %+v, %v", got.Records, err)
	}
}

func TestParseCloudParsers(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "gcp.json", `{"prefixes":[{"ipv4Prefix":"1.2.3.0/24","service":"s","scope":"r"},{"ipv6Prefix":"2606:4700::/32"}]}`)
	writeTestFile(t, dir, "oracle.json", `{"regions":[{"region":"r","cidrs":[{"cidr":"1.2.4.0/24","tags":["a","b"]}]}]}`)
	writeTestFile(t, dir, "do.csv", "1.2.5.0/24,DE\n# comment\nbad\n")
	writeTestFile(t, dir, "linode.csv", "1.2.6.0/24,US\n")
	writeTestFile(t, dir, "fastly.json", `{"addresses":["1.2.7.0/24"],"ipv6_addresses":["2606:4700::/32"]}`)
	if got, err := parseGCP(dir, []string{"gcp.json"}); err != nil || len(got.Records) != 2 {
		t.Fatalf("gcp = %+v, %v", got, err)
	}
	if got, err := parseOracle(dir, []string{"oracle.json"}); err != nil || len(got.Records) != 1 {
		t.Fatalf("oracle = %+v, %v", got, err)
	}
	if got, err := parseDigitalOcean(dir, []string{"do.csv"}); err != nil || len(got.Records) != 1 {
		t.Fatalf("digitalocean = %+v, %v", got, err)
	}
	if got, err := parseLinode(dir, []string{"linode.csv"}); err != nil || len(got.Records) != 1 {
		t.Fatalf("linode = %+v, %v", got, err)
	}
	if got, err := parseFastly(dir, []string{"fastly.json"}); err != nil || len(got.Records) != 2 {
		t.Fatalf("fastly = %+v, %v", got, err)
	}
}

func TestParseCloudErrors(t *testing.T) {
	dir := t.TempDir()
	for _, parse := range []func(string, []string) (parsedSource, error){
		parseAWS, parseGCP, parseOracle, parseFastly, parseDigitalOcean, parseLinode,
	} {
		if _, err := parse(dir, []string{"missing"}); err == nil {
			t.Fatalf("%T missing file should fail", parse)
		}
	}
	for _, name := range []string{"aws.json", "gcp.json", "oracle.json", "fastly.json"} {
		writeTestFile(t, dir, name, "{")
	}
	if _, err := parseAWS(dir, []string{"aws.json"}); err == nil {
		t.Fatal("bad aws JSON should fail")
	}
	if _, err := parseGCP(dir, []string{"gcp.json"}); err == nil {
		t.Fatal("bad gcp JSON should fail")
	}
	if _, err := parseOracle(dir, []string{"oracle.json"}); err == nil {
		t.Fatal("bad oracle JSON should fail")
	}
	if _, err := parseFastly(dir, []string{"fastly.json"}); err == nil {
		t.Fatal("bad fastly JSON should fail")
	}
	writeTestFile(t, dir, "gcp-bad.json", `{"prefixes":[{"ipv4Prefix":"bad"}]}`)
	if _, err := parseGCP(dir, []string{"gcp-bad.json"}); err == nil {
		t.Fatal("bad gcp CIDR should fail")
	}
	writeTestFile(t, dir, "oracle-bad.json", `{"regions":[{"region":"r","cidrs":[{"cidr":"bad"}]}]}`)
	if _, err := parseOracle(dir, []string{"oracle-bad.json"}); err == nil {
		t.Fatal("bad oracle CIDR should fail")
	}
	writeTestFile(t, dir, "fastly-bad.json", `{"addresses":["bad"]}`)
	if _, err := parseFastly(dir, []string{"fastly-bad.json"}); err == nil {
		t.Fatal("bad fastly CIDR should fail")
	}
	writeTestFile(t, dir, "aws-bad.json", `{"prefixes":[{"ip_prefix":"bad"}]}`)
	if _, err := parseAWS(dir, []string{"aws-bad.json"}); err == nil {
		t.Fatal("bad aws CIDR should fail")
	}
	writeTestFile(t, dir, "aws-bad6.json", `{"ipv6_prefixes":[{"ipv6_prefix":"bad"}]}`)
	if _, err := parseAWS(dir, []string{"aws-bad6.json"}); err == nil {
		t.Fatal("bad aws IPv6 CIDR should fail")
	}
}

func TestParseCSVFirstPrefixErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := parseCSVFirstPrefix(dir, "missing", "p", "hosting", 1); err == nil {
		t.Fatal("missing CSV should fail")
	}
	writeTestFile(t, dir, "long.csv", strings.Repeat("x", 2*1024*1024+1))
	if _, err := parseCSVFirstPrefix(dir, "long.csv", "p", "hosting", 1); err == nil {
		t.Fatal("long CSV line should fail")
	}
}

func TestAppendCloudErrors(t *testing.T) {
	var out parsedSource
	if err := appendCloud(&out, "", "p", "s", "r", "hosting", 1); err != nil {
		t.Fatal(err)
	}
	if err := appendCloud(&out, "bad", "p", "s", "r", "hosting", 1); err == nil {
		t.Fatal("bad cloud CIDR should fail")
	}
}
