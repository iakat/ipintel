package ipintel

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testRecord(t *testing.T, cidr string, sourceID uint16, category string, confidence uint8, asn uint32, org, country, detail string) Record {
	t.Helper()
	p, err := parsePrefix(cidr)
	if err != nil {
		t.Fatal(err)
	}
	r := recordFromPrefix(p, category, confidence, detail)
	r.SourceID = sourceID
	r.ASN, r.Org, r.Country = asn, org, country
	return r
}

func TestDatabaseRoundTrip(t *testing.T) {
	sources := []SourceMeta{
		{ID: 0, Name: "openasn"},
		{ID: 1, Name: "x4b-datacenter"},
		{ID: 2, Name: "pomerium-vpn"},
		{ID: 3, Name: "geolite2-asn"},
		{ID: 4, Name: "geolite2-country"},
		{ID: 5, Name: "x4b-vpn"},
		{ID: 6, Name: "tor-exit"},
		{ID: 7, Name: "bad-asn-list"},
	}
	records := []Record{
		testRecord(t, "8.8.8.0/24", 0, "hosting", 80, 15169, "Google", "", `{"test":"openasn"}`),
		testRecord(t, "8.8.8.0/24", 1, "hosting", 80, 0, "", "", `{"test":"x4b-dc"}`),
		testRecord(t, "8.8.8.0/24", 2, "vpn_candidate", 90, 0, "", "", `{"test":"pomerium"}`),
		testRecord(t, "8.8.8.0/24", 3, "info", 0, 15169, "Google LLC", "", `{"test":"asn"}`),
		testRecord(t, "8.8.8.0/24", 4, "country", 0, 0, "", "US", `{"country":"US"}`),
		testRecord(t, "1.2.3.4/32", 5, "vpn", 85, 0, "", "", `{"test":"vpn"}`),
		testRecord(t, "2001:db8::/32", 0, "hosting", 80, 0, "", "", `{"test":"v6"}`),
	}
	sortRecords(records)
	manifest := &Manifest{
		FormatVersion: FormatVersion,
		BuiltAt:       time.Unix(100, 0).UTC(),
		BlockSize:     2,
		Sources:       sources,
		ASNs:          map[uint32]string{15169: "Google"},
	}
	path := filepath.Join(t.TempDir(), "test.bin")
	if err := writeDatabase(path, records, manifest); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Size() == 0 {
		t.Fatalf("database not written: %v", err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	res, err := db.Lookup("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if res.ASN != 15169 || res.Org != "Google" || res.Country != "US" {
		t.Fatalf("metadata = %+v", res)
	}
	if res.Score != 36 || res.Verdict != "hosting" {
		t.Fatalf("score/verdict = %d/%s", res.Score, res.Verdict)
	}
	if !hasEvidence(res.Evidence, "bad-asn-list", "hosting") {
		t.Fatal("bad-asn evidence missing")
	}
	if res.Evidence[0].Source == "" {
		t.Fatal("empty evidence source")
	}

	res, err = db.Lookup("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if res.Score != 68 || res.Verdict != "vpn" {
		t.Fatalf("vpn score/verdict = %d/%s", res.Score, res.Verdict)
	}

	res, err = db.Lookup("2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Score != 36 || res.Verdict != "hosting" {
		t.Fatalf("ipv6 score/verdict = %d/%s", res.Score, res.Verdict)
	}

	res, err = db.Lookup("203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Score != 0 || res.Verdict != "unknown" {
		t.Fatalf("unknown score/verdict = %d/%s", res.Score, res.Verdict)
	}

	mem, err := OpenInMemory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	res, err = mem.Lookup("8.8.8.8")
	if err != nil || res.Score != 36 || res.Verdict != "hosting" {
		t.Fatalf("in-memory lookup = %+v, %v", res, err)
	}
}

func hasEvidence(ev []Evidence, source, category string) bool {
	for _, e := range ev {
		if e.Source == source && e.Category == category && e.Matched {
			return true
		}
	}
	return false
}

func TestPrefixRange(t *testing.T) {
	p := netip.MustParsePrefix("192.0.2.0/24")
	family, start, end := prefixRange(p)
	if family != 4 || addrString(family, start) != "192.0.2.0" || addrString(family, end) != "192.0.2.255" {
		t.Fatalf("v4 range = %d %s-%s", family, addrString(family, start), addrString(family, end))
	}
	p = netip.MustParsePrefix("2001:db8::/126")
	family, start, end = prefixRange(p)
	if family != 6 || addrString(family, start) != "2001:db8::" || addrString(family, end) != "2001:db8::3" {
		t.Fatalf("v6 range = %d %s-%s", family, addrString(family, start), addrString(family, end))
	}
}
