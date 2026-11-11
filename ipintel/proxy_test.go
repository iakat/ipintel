package ipintel

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func findRecord(t *testing.T, records []Record, ip string) Record {
	t.Helper()
	p, err := parsePrefix(ip)
	if err != nil {
		t.Fatal(err)
	}
	family, start, _ := prefixRange(p)
	for _, r := range records {
		if r.Family == family && bytes.Equal(r.Start[:], start[:]) {
			return r
		}
	}
	t.Fatalf("record %s not found", ip)
	return Record{}
}

func detailFields(t *testing.T, r Record) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Detail), &m); err != nil {
		t.Fatalf("detail %q: %v", r.Detail, err)
	}
	return m
}

func TestParseOpenProxiesGroup(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "open-proxies-monosans.json", `[
		{"protocol":"socks5","host":"1.2.3.4","port":1080,"exit_ip":"5.6.7.8","asn":{"autonomous_system_number":64500,"autonomous_system_organization":"Home ISP"},"geolocation":{"country":{"iso_code":"us"}}},
		{"protocol":"http","host":"1.2.3.5","port":8080,"exit_ip":"1.2.3.5"},
		{"protocol":"http","host":"bad","port":1},
		{"protocol":"http","host":"1.2.3.9","port":1,"exit_ip":"bad"},
		{"host":"1.2.3.8","port":1}
	]`)
	writeTestFile(t, dir, "open-proxies-clearproxy-socks4.txt", "1.2.3.4:4145\n1.2.3.6:4145\n")
	writeTestFile(t, dir, "open-proxies-clearproxy-http.txt", "1.2.3.4:8080\n1.2.3.8:3128\n")
	writeTestFile(t, dir, "open-proxies-clearproxy-socks5.txt", "1.2.3.4:1081\n")
	writeTestFile(t, dir, "open-proxies-iplocate.txt", "socks5://1.2.3.4:1080\nsocks4://1.2.3.7:4145\n")

	got, err := parseOpenProxies(dir, []string{
		"open-proxies-monosans.json",
		"open-proxies-clearproxy-socks4.txt",
		"open-proxies-clearproxy-http.txt",
		"open-proxies-clearproxy-socks5.txt",
		"open-proxies-iplocate.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 7 {
		t.Fatalf("records = %d, want 7: %+v", len(got.Records), got.Records)
	}
	merged := findRecord(t, got.Records, "1.2.3.4")
	if merged.Category != "proxy" || merged.Confidence != 85 {
		t.Fatalf("merged = %+v", merged)
	}
	detail := detailFields(t, merged)
	if len(detail["sources"].([]any)) != 3 {
		t.Fatalf("sources = %v", detail["sources"])
	}
	if len(detail["roles"].([]any)) != 2 {
		t.Fatalf("roles = %v", detail["roles"])
	}
	exit := findRecord(t, got.Records, "5.6.7.8")
	if exit.ASN != 64500 || exit.Org != "Home ISP" || exit.Country != "US" {
		t.Fatalf("exit metadata = %+v", exit)
	}
	exitDetail := detailFields(t, exit)
	if exitDetail["derived"] != nil {
		t.Fatalf("unexpected derived detail = %v", exitDetail)
	}
	if len(exitDetail["proxy_hosts"].([]any)) != 1 {
		t.Fatalf("proxy_hosts = %v", exitDetail["proxy_hosts"])
	}
	same := findRecord(t, got.Records, "1.2.3.5")
	if same.Confidence != 70 {
		t.Fatalf("same host/exit confidence = %d", same.Confidence)
	}
	if roles := detailFields(t, same)["roles"].([]any); len(roles) != 1 || roles[0] != "proxy" {
		t.Fatalf("same host/exit roles = %v", roles)
	}
	if r := findRecord(t, got.Records, "1.2.3.6"); detailFields(t, r)["protocols"].([]any)[0] != "socks4" {
		t.Fatalf("socks4 hint = %+v", r)
	}
	if r := findRecord(t, got.Records, "1.2.3.7"); detailFields(t, r)["protocols"].([]any)[0] != "socks4" {
		t.Fatalf("socks4 scheme = %+v", r)
	}
	two := findRecord(t, got.Records, "1.2.3.8")
	if two.Confidence != 80 {
		t.Fatalf("two-source confidence = %d", two.Confidence)
	}
	if detailFields(t, two)["proxy"] != "http" {
		t.Fatalf("default protocol = %v", detailFields(t, two))
	}
}

func TestProxyAddInvalid(t *testing.T) {
	p := newProxyParser()
	p.add(netip.Addr{}, "proxy", "http", "80", "test", "", 0, "", "")
	if got := p.result(); len(got.Records) != 0 {
		t.Fatalf("invalid add = %+v", got)
	}
}

func TestProxySourceHelpers(t *testing.T) {
	if got := proxySourceLabel("open-proxies-custom.txt"); got != "open-proxies-custom" {
		t.Fatalf("source label = %q", got)
	}
	if got := proxyProtocolHint("open-proxies-clearproxy-socks5.txt"); got != "socks5" {
		t.Fatalf("socks5 hint = %q", got)
	}
	if got := proxyProtocolHint("open-proxies-clearproxy-socks4.txt"); got != "socks4" {
		t.Fatalf("socks4 hint = %q", got)
	}
	if got := proxyProtocolHint("open-proxies-iplocate.txt"); got != "http" {
		t.Fatalf("http hint = %q", got)
	}
}

func TestParseOpenProxyJSONErrors(t *testing.T) {
	dir := t.TempDir()
	if err := parseOpenProxyJSON(filepath.Join(dir, "missing.json"), "missing.json", newProxyParser()); err == nil {
		t.Fatal("missing JSON should fail")
	}
	writeTestFile(t, dir, "bad.json", "{")
	if err := parseOpenProxyJSON(filepath.Join(dir, "bad.json"), "bad.json", newProxyParser()); err == nil {
		t.Fatal("bad JSON should fail")
	}
	writeTestFile(t, dir, "empty.json", "[]")
	got, err := parseOpenProxies(dir, []string{"empty.json"})
	if err != nil || len(got.Records) != 0 {
		t.Fatalf("empty JSON = %+v, %v", got, err)
	}
}

func TestParseOpenProxyTextErrors(t *testing.T) {
	dir := t.TempDir()
	if err := parseOpenProxyText(filepath.Join(dir, "missing.txt"), "missing.txt", newProxyParser()); err == nil {
		t.Fatal("missing text should fail")
	}
	writeTestFile(t, dir, "long.txt", string(make([]byte, 1024*1024+1)))
	// make() returns NUL bytes, which are invalid in a line but still a long
	// scanner token; the scanner must report ErrTooLong.
	if _, err := parseOpenProxies(dir, []string{"long.txt"}); err == nil {
		t.Fatal("long text line should fail")
	}
	writeTestFile(t, dir, "empty.txt", "")
	got, err := parseOpenProxies(dir, []string{"empty.txt"})
	if err != nil || len(got.Records) != 0 {
		t.Fatalf("empty text = %+v, %v", got, err)
	}
	writeTestFile(t, dir, "bad.txt", "# comment\nhttp://[::1\nhttp:///missing\n999.999.999.999:1\n")
	got, err = parseOpenProxies(dir, []string{"bad.txt"})
	if err != nil || len(got.Records) != 0 {
		t.Fatalf("bad text = %+v, %v", got.Records, err)
	}
}

func gzipBytes(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseIPGeoVPN(t *testing.T) {
	dir := t.TempDir()
	body := "network,provider,basis\n1.2.3.0/24,Example VPN,asn\n2001:db8::/32,Other,cluster\n1.2.4.0/24\n1.2.5.0/24,OnlyProvider\nbad,Ignored,\n,Ignored,\n"
	if err := os.WriteFile(filepath.Join(dir, "ipgeo-vpn.csv.gz"), gzipBytes(t, body), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := parseIPGeoVPN(dir, []string{"ipgeo-vpn.csv.gz"})
	if err != nil || len(got.Records) != 4 {
		t.Fatalf("ipgeo vpn = %+v, %v", got.Records, err)
	}
	if got.Records[0].Category != "vpn" || got.Records[0].Confidence != 80 {
		t.Fatalf("vpn record = %+v", got.Records[0])
	}
	if detail := detailFields(t, got.Records[0]); detail["provider"] != "Example VPN" || detail["basis"] != "asn" {
		t.Fatalf("vpn detail = %v", detail)
	}
	if detail := detailFields(t, got.Records[2]); len(detail) != 0 {
		t.Fatalf("minimal vpn detail = %v", detail)
	}
	if detail := detailFields(t, got.Records[3]); detail["provider"] != "OnlyProvider" || detail["basis"] != nil {
		t.Fatalf("provider-only detail = %v", detail)
	}
	if got.Records[1].Family != 6 {
		t.Fatalf("ipv6 vpn family = %d", got.Records[1].Family)
	}
}

func TestParseIPGeoVPNErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := parseIPGeoVPN(dir, []string{"missing.csv.gz"}); err == nil {
		t.Fatal("missing gzip should fail")
	}
	writeTestFile(t, dir, "notgzip.csv.gz", "plain")
	if _, err := parseIPGeoVPN(dir, []string{"notgzip.csv.gz"}); err == nil {
		t.Fatal("bad gzip should fail")
	}
	if err := os.WriteFile(filepath.Join(dir, "badcsv.csv.gz"), gzipBytes(t, "\"unterminated\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := parseIPGeoVPN(dir, []string{"badcsv.csv.gz"}); err == nil {
		t.Fatal("bad csv should fail")
	}
}

func TestParseCloudCN(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "cloud-cn-aliyun-ipv4.txt", "1.2.3.0/24\n")
	writeTestFile(t, dir, "cloud-cn-tencent-ipv6.txt", "2001:db8::/32\n")
	got, err := parseCloudCN(dir, []string{"cloud-cn-aliyun-ipv4.txt", "cloud-cn-tencent-ipv6.txt"})
	if err != nil || len(got.Records) != 2 {
		t.Fatalf("cloud-cn = %+v, %v", got.Records, err)
	}
	if got.Records[0].Category != "hosting" || got.Records[0].Confidence != 90 {
		t.Fatalf("cloud-cn record = %+v", got.Records[0])
	}
	if detail := detailFields(t, got.Records[0]); detail["provider"] != "aliyun" || detail["list"] != "axpwx" {
		t.Fatalf("cloud-cn detail = %v", detail)
	}
	if detail := detailFields(t, got.Records[1]); detail["provider"] != "tencent" {
		t.Fatalf("cloud-cn ipv6 detail = %v", detail)
	}
}

func TestCloudCNProvider(t *testing.T) {
	tests := map[string]string{
		"cloud-cn-aliyun-ipv4.txt":  "aliyun",
		"cloud-cn-tencent-ipv6.txt": "tencent",
		"weird.txt":                 "weird",
	}
	for name, want := range tests {
		if got := cloudCNProvider(name); got != want {
			t.Errorf("cloudCNProvider(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestParseCloudCNErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := parseCloudCN(dir, []string{"missing.txt"}); err == nil {
		t.Fatal("missing cloud file should fail")
	}
	writeTestFile(t, dir, "bad.txt", "not-a-cidr\n")
	if _, err := parseCloudCN(dir, []string{"bad.txt"}); err == nil {
		t.Fatal("bad cloud CIDR should fail")
	}
}

func TestHexydecDatacenter(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "hexydec-datacentres-ipv4.txt", "1.2.3.0/24\n")
	writeTestFile(t, dir, "hexydec-datacentres-ipv6.txt", "2001:db8::/32\n")
	spec := findSpec(t, "hexydec-datacenter")
	got, err := spec.Parse(dir, []string{"hexydec-datacentres-ipv4.txt", "hexydec-datacentres-ipv6.txt"})
	if err != nil || len(got.Records) != 2 {
		t.Fatalf("hexydec = %+v, %v", got.Records, err)
	}
	if got.Records[0].Category != "hosting" || got.Records[0].Confidence != 80 {
		t.Fatalf("hexydec record = %+v", got.Records[0])
	}
	if detail := detailFields(t, got.Records[0]); detail["list"] != "hexydec-datacentres" {
		t.Fatalf("hexydec detail = %v", detail)
	}
	if _, err := spec.Parse(dir, []string{"missing.txt"}); err == nil {
		t.Fatal("missing hexydec file should fail")
	}
}
