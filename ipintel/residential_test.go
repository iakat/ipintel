package ipintel

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func TestDeriveResidentialProxies(t *testing.T) {
	openASN := []Record{
		testRecord(t, "1.2.3.0/24", 0, "residential_isp", 60, 64500, "Home ISP", "", `{}`),
		testRecord(t, "1.2.4.0/24", 0, "mobile", 80, 64501, "Mobile", "", `{}`),
		testRecord(t, "1.2.5.0/24", 0, "business", 50, 64502, "Business", "", `{}`),
		testRecord(t, "1.2.6.0/24", 0, "hosting", 80, 64503, "Hosting", "", `{}`),
		testRecord(t, "2001:db8::/32", 0, "residential_isp", 60, 64504, "Home IPv6", "", `{}`),
		testRecord(t, "2.0.0.0/16", 0, "residential_isp", 60, 64505, "Wide", "", `{}`),
		testRecord(t, "2.0.1.0/24", 0, "mobile", 80, 64506, "Narrow", "", `{}`),
	}
	records := []Record{
		testRecord(t, "1.2.3.4/32", 1, "proxy", 70, 0, "", "", `{"sources":["monosans"]}`),
		testRecord(t, "1.2.4.4/32", 1, "proxy", 80, 0, "", "", `{}`),
		testRecord(t, "1.2.5.4/32", 1, "proxy", 70, 0, "", "", `{}`),
		testRecord(t, "1.2.6.4/32", 1, "proxy", 70, 0, "", "", `{}`),
		testRecord(t, "203.0.113.1/32", 1, "proxy", 70, 0, "", "", `{"sources":["iplocate"]}`),
		testRecord(t, "2001:db8::1/128", 1, "proxy", 70, 0, "", "", `{}`),
		testRecord(t, "2.0.1.5/32", 1, "proxy", 70, 0, "", "", `{}`),
		testRecord(t, "3.0.0.1/32", 1, "hosting", 80, 0, "", "", `{}`),
		testRecord(t, "4.0.0.1/32", 1, "residential_proxy", 96, 0, "", "", `{}`),
		testRecord(t, "1.2.3.5/32", 1, "proxy", 70, 0, "", `{"bad":`, ""),
	}
	deriveResidentialProxies(records, openASN)

	residential := findRecord(t, records, "1.2.3.4")
	if residential.Category != "residential_proxy" || residential.Confidence != 95 {
		t.Fatalf("residential = %+v", residential)
	}
	if residential.ASN != 64500 || residential.Org != "Home ISP" || residential.Country != "" {
		t.Fatalf("residential metadata = %+v", residential)
	}
	detail := detailFields(t, residential)
	if detail["network_category"] != "residential_isp" || detail["derived"] != "residential_proxy" || detail["derived_from"] != "openasn" {
		t.Fatalf("residential detail = %v", detail)
	}
	if detail["asn"] != float64(64500) || detail["org"] != "Home ISP" {
		t.Fatalf("residential ASN detail = %v", detail)
	}

	mobile := findRecord(t, records, "1.2.4.4")
	if mobile.Category != "residential_proxy" || mobile.Confidence != 85 {
		t.Fatalf("mobile = %+v", mobile)
	}
	if business := findRecord(t, records, "1.2.5.4"); business.Category != "proxy" || detailFields(t, business)["network_category"] != "business" {
		t.Fatalf("business = %+v", business)
	}
	if hosting := findRecord(t, records, "1.2.6.4"); hosting.Category != "proxy" || detailFields(t, hosting)["network_category"] != "hosting" {
		t.Fatalf("hosting = %+v", hosting)
	}
	unmatched := findRecord(t, records, "203.0.113.1")
	if unmatched.Category != "proxy" {
		t.Fatalf("unmatched = %+v", unmatched)
	}
	if len(detailFields(t, unmatched)) != 1 {
		t.Fatalf("unmatched detail = %v", detailFields(t, unmatched))
	}
	if v6 := findRecord(t, records, "2001:db8::1"); v6.Category != "residential_proxy" || v6.Confidence != 95 {
		t.Fatalf("ipv6 = %+v", v6)
	}
	narrow := findRecord(t, records, "2.0.1.5")
	if narrow.Category != "residential_proxy" || narrow.Confidence != 85 || detailFields(t, narrow)["network_category"] != "mobile" {
		t.Fatalf("narrow = %+v", narrow)
	}
	if ignored := findRecord(t, records, "3.0.0.1"); ignored.Category != "hosting" {
		t.Fatalf("hosting input changed = %+v", ignored)
	}
	if already := findRecord(t, records, "4.0.0.1"); already.Category != "residential_proxy" || already.Confidence != 96 {
		t.Fatalf("already residential = %+v", already)
	}
	if bad := findRecord(t, records, "1.2.3.5"); bad.Category != "residential_proxy" || detailFields(t, bad)["network_category"] != "residential_isp" {
		t.Fatalf("bad detail input = %+v", bad)
	}
}

func TestDeriveResidentialNoNetwork(t *testing.T) {
	records := []Record{testRecord(t, "1.2.3.4/32", 1, "proxy", 70, 0, "", "", `{}`)}
	deriveResidentialProxies(records, nil)
	if records[0].Category != "proxy" {
		t.Fatalf("no network changed record = %+v", records[0])
	}
}

func TestRangeIndex(t *testing.T) {
	idx := newRangeIndex(nil)
	family, addr := addrBytes(netip.MustParseAddr("1.2.3.4"))
	if _, ok := idx.find(family, addr); ok {
		t.Fatal("empty index should not match")
	}
	if _, ok := idx.find(5, addr); ok {
		t.Fatal("unknown family should not match")
	}

	records := []Record{
		testRecord(t, "2.0.0.0/16", 0, "residential_isp", 60, 0, "", "", `{}`),
		testRecord(t, "2.0.0.0/24", 0, "mobile", 80, 0, "", "", `{}`),
		testRecord(t, "2.0.1.0/24", 0, "mobile", 80, 0, "", "", `{}`),
	}
	idx = newRangeIndex(records)
	family, addr = addrBytes(netip.MustParseAddr("2.0.1.5"))
	found, ok := idx.find(family, addr)
	if !ok || found.Category != "mobile" {
		t.Fatalf("nested find = %+v, %v", found, ok)
	}
	family, addr = addrBytes(netip.MustParseAddr("2.0.2.5"))
	found, ok = idx.find(family, addr)
	if !ok || found.Category != "residential_isp" {
		t.Fatalf("wide find = %+v, %v", found, ok)
	}
	family, addr = addrBytes(netip.MustParseAddr("2.0.0.5"))
	found, ok = idx.find(family, addr)
	if !ok || found.Category != "mobile" || found.Start != records[1].Start {
		t.Fatalf("same-start find = %+v, %v", found, ok)
	}
	family, addr = addrBytes(netip.MustParseAddr("3.0.0.1"))
	if _, ok := idx.find(family, addr); ok {
		t.Fatal("outside index should not match")
	}
}

func TestDetailObject(t *testing.T) {
	if got := detailObject(""); len(got) != 0 {
		t.Fatalf("empty detail = %v", got)
	}
	if got := detailObject("{"); len(got) != 0 {
		t.Fatalf("bad detail = %v", got)
	}
	if got := detailObject(`{"a":1}`); got["a"] != float64(1) {
		t.Fatalf("detail = %v", got)
	}
}

func TestBuildDerivesResidentialProxy(t *testing.T) {
	raw := t.TempDir()
	writeTestMMDB(t, raw, "openasn.mmdb", map[string]mmdbtype.Map{
		"1.2.3.0/24": {
			"asn":          mmdbtype.Uint32(64500),
			"as_org":       mmdbtype.String("Home ISP"),
			"core_verdict": mmdbtype.String("residential_isp"),
		},
	})
	if err := os.WriteFile(filepath.Join(raw, "openasn-build.json"), []byte(`{"build_id":"b"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raw, "openasn-checksums.txt"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raw, "open-proxies-clearproxy-http.txt"), []byte("1.2.3.4:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "db")
	m, err := Build(BuildOptions{
		RawDir: raw, OutFile: out,
		Exclude: excludeAllExcept("openasn", "open-proxies"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.RecordCount != 2 {
		t.Fatalf("manifest = %+v", m)
	}
	db, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Lookup("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if res.Score != 90 || res.Verdict != "residential_proxy" {
		t.Fatalf("lookup = %+v", res)
	}
	found := false
	for _, ev := range res.Evidence {
		if ev.Source == "open-proxies" && ev.Category == "residential_proxy" && ev.Matched {
			found = true
			var detail map[string]any
			if err := json.Unmarshal(ev.Detail, &detail); err != nil {
				t.Fatal(err)
			}
			if detail["network_category"] != "residential_isp" {
				t.Fatalf("evidence detail = %v", detail)
			}
		}
	}
	if !found {
		t.Fatalf("residential evidence missing: %+v", res.Evidence)
	}
}
