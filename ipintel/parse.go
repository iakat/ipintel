package ipintel

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

type networksReader interface {
	Next() bool
	Network(result any) (*net.IPNet, error)
	Err() error
}

func parseCIDRText(dir string, files []string, category string, confidence uint8, extra map[string]any) (parsedSource, error) {
	var out parsedSource
	for _, name := range files {
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			return out, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := sc.Text()
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			for _, token := range strings.Fields(line) {
				p, err := parsePrefix(token)
				if err != nil {
					f.Close()
					return out, fmt.Errorf("%s:%d: %w", name, lineNo, err)
				}
				out.Records = append(out.Records, recordFromPrefix(p, category, confidence, detailForCIDR(token, extra)))
			}
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func parseIPFile(category string, confidence uint8, extra map[string]any) func(string, []string) (parsedSource, error) {
	return func(dir string, files []string) (parsedSource, error) {
		return parseCIDRText(dir, files, category, confidence, extra)
	}
}

func parsePrefix(token string) (netip.Prefix, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return netip.Prefix{}, fmt.Errorf("empty address")
	}
	if strings.Contains(token, "/") {
		p, err := netip.ParsePrefix(token)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(token)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func recordFromPrefix(p netip.Prefix, category string, confidence uint8, detail string) Record {
	family, start, end := prefixRange(p)
	return Record{
		Family: family, Start: start, End: end,
		Category: category, Confidence: confidence, Detail: detail,
	}
}

func recordFromAddr(a netip.Addr, category string, confidence uint8, detail string) Record {
	a = a.Unmap()
	return recordFromPrefix(netip.PrefixFrom(a, a.BitLen()), category, confidence, detail)
}

func detailForCIDR(token string, extra map[string]any) string {
	m := make(map[string]any, len(extra)+1)
	for k, v := range extra {
		m[k] = v
	}
	m["cidr"] = token
	return detailJSON(m)
}

func parseProviderIPs(dir string, files []string) (parsedSource, error) {
	var out parsedSource
	for _, name := range files {
		provider := strings.TrimSuffix(strings.TrimPrefix(name, "vpn-provider-"), ".txt")
		parsed, err := parseCIDRText(dir, []string{name}, "vpn", 90, map[string]any{"provider": provider})
		if err != nil {
			return out, err
		}
		out.Records = append(out.Records, parsed.Records...)
	}
	return out, nil
}

func parsePomerium(dir string, files []string) (parsedSource, error) {
	var out parsedSource
	b, err := os.ReadFile(filepath.Join(dir, files[0]))
	if err != nil {
		return out, err
	}
	var rows []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		return out, fmt.Errorf("pomerium vpnlist: %w", err)
	}
	for _, row := range rows {
		p, err := parsePrefix(row.ID)
		if err != nil {
			return out, fmt.Errorf("pomerium vpnlist %q: %w", row.ID, err)
		}
		out.Records = append(out.Records, recordFromPrefix(p, "vpn_candidate", 60, detailForCIDR(row.ID, map[string]any{"list": "pomerium"})))
	}
	return out, nil
}

func parseBadASN(dir string, files []string) (parsedSource, error) {
	out := parsedSource{ASNs: map[uint32]string{}}
	f, err := os.Open(filepath.Join(dir, files[0]))
	if err != nil {
		return out, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return out, err
	}
	for i, row := range rows {
		if i == 0 || len(row) < 2 {
			continue
		}
		asn := strings.TrimSpace(row[0])
		asn = strings.TrimPrefix(strings.ToUpper(asn), "AS")
		n, err := strconv.ParseUint(asn, 10, 32)
		if err != nil {
			continue
		}
		entity := strings.TrimSpace(row[1])
		if entity != "" {
			out.ASNs[uint32(n)] = entity
		}
	}
	return out, nil
}

func parseOpenASN(dir string, files []string) (parsedSource, error) {
	r, err := maxminddb.Open(filepath.Join(dir, files[0]))
	if err != nil {
		return parsedSource{}, err
	}
	defer r.Close()
	return parseOpenASNNetworks(r.Networks(maxminddb.SkipAliasedNetworks))
}

func parseOpenASNNetworks(networks networksReader) (parsedSource, error) {
	var out parsedSource

	type rec struct {
		ASN             uint32   `maxminddb:"asn"`
		ASOrg           string   `maxminddb:"as_org"`
		Category        string   `maxminddb:"category"`
		NetworkRole     string   `maxminddb:"network_role"`
		BadASN          bool     `maxminddb:"bad_asn"`
		VPNProvider     bool     `maxminddb:"vpn_provider"`
		MobileCarrier   bool     `maxminddb:"mobile_carrier"`
		EnterpriseGW    bool     `maxminddb:"enterprise_gw"`
		CDN             bool     `maxminddb:"cdn"`
		HostingExtra    bool     `maxminddb:"hosting_extra"`
		VPNRange        bool     `maxminddb:"vpn_range"`
		DatacenterRange bool     `maxminddb:"datacenter_range"`
		CoreVerdict     string   `maxminddb:"core_verdict"`
		CoreSources     []string `maxminddb:"core_sources"`
	}

	for networks.Next() {
		var rr rec
		n, err := networks.Network(&rr)
		if err != nil {
			return out, err
		}
		p, err := netip.ParsePrefix(n.String())
		if err != nil {
			return out, err
		}
		verdict := rr.CoreVerdict
		if verdict == "" {
			verdict = "unknown"
		}
		detail := detailJSON(map[string]any{
			"verdict":      verdict,
			"sources":      rr.CoreSources,
			"asn":          rr.ASN,
			"org":          rr.ASOrg,
			"category":     rr.Category,
			"network_role": rr.NetworkRole,
			"flags": map[string]bool{
				"bad_asn":          rr.BadASN,
				"vpn_provider":     rr.VPNProvider,
				"mobile_carrier":   rr.MobileCarrier,
				"enterprise_gw":    rr.EnterpriseGW,
				"cdn":              rr.CDN,
				"hosting_extra":    rr.HostingExtra,
				"vpn_range":        rr.VPNRange,
				"datacenter_range": rr.DatacenterRange,
			},
		})
		record := recordFromPrefix(p, verdict, openASNConfidence(verdict, rr.CoreSources), detail)
		record.ASN = rr.ASN
		record.Org = rr.ASOrg
		out.Records = append(out.Records, record)
	}
	if err := networks.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func openASNConfidence(verdict string, sources []string) uint8 {
	has := func(want string) bool {
		for _, s := range sources {
			if s == want {
				return true
			}
		}
		return false
	}
	switch verdict {
	case "vpn":
		if has("x4b_vpn") {
			return 85
		}
		if has("asn_vpn_provider") {
			return 80
		}
		return 75
	case "hosting":
		switch {
		case has("x4b_dc"):
			return 80
		case has("asn_hosting_extra"):
			return 75
		case has("asn_bad_asn"):
			return 60
		case has("asn_cdn"):
			return 50
		case has("asn_category"):
			return 55
		default:
			return 70
		}
	case "mobile":
		return 80
	case "residential_isp":
		return 60
	case "business", "education", "government":
		return 50
	default:
		return 0
	}
}

func parseGeoLiteCountry(dir string, files []string) (parsedSource, error) {
	r, err := maxminddb.Open(filepath.Join(dir, files[0]))
	if err != nil {
		return parsedSource{}, err
	}
	defer r.Close()
	return parseGeoLiteCountryNetworks(r.Networks(maxminddb.SkipAliasedNetworks))
}

func parseGeoLiteCountryNetworks(networks networksReader) (parsedSource, error) {
	var out parsedSource
	type rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	for networks.Next() {
		var rr rec
		n, err := networks.Network(&rr)
		if err != nil {
			return out, err
		}
		p, err := netip.ParsePrefix(n.String())
		if err != nil {
			return out, err
		}
		country := strings.ToUpper(rr.Country.ISOCode)
		record := recordFromPrefix(p, "country", 0, detailJSON(map[string]any{"country": country}))
		record.Country = country
		out.Records = append(out.Records, record)
	}
	if err := networks.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func parseGeoLiteASN(dir string, files []string) (parsedSource, error) {
	r, err := maxminddb.Open(filepath.Join(dir, files[0]))
	if err != nil {
		return parsedSource{}, err
	}
	defer r.Close()
	return parseGeoLiteASNNetworks(r.Networks(maxminddb.SkipAliasedNetworks))
}

func parseGeoLiteASNNetworks(networks networksReader) (parsedSource, error) {
	var out parsedSource
	type rec struct {
		ASN uint32 `maxminddb:"autonomous_system_number"`
		Org string `maxminddb:"autonomous_system_organization"`
	}
	for networks.Next() {
		var rr rec
		n, err := networks.Network(&rr)
		if err != nil {
			return out, err
		}
		p, err := netip.ParsePrefix(n.String())
		if err != nil {
			return out, err
		}
		record := recordFromPrefix(p, "info", 0, detailJSON(map[string]any{
			"asn": rr.ASN, "org": rr.Org,
		}))
		record.ASN = rr.ASN
		record.Org = rr.Org
		out.Records = append(out.Records, record)
	}
	if err := networks.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func parseICloudRelay(dir string, files []string) (parsedSource, error) {
	var out parsedSource
	f, err := os.Open(filepath.Join(dir, files[0]))
	if err != nil {
		return out, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	rows, err := r.ReadAll()
	if err != nil {
		return out, err
	}
	for _, row := range rows {
		p, err := parsePrefix(row[0])
		if err != nil {
			continue // header or malformed line
		}
		detail := map[string]any{"provider": "icloud-private-relay"}
		if len(row) > 1 {
			detail["country"] = row[1]
		}
		if len(row) > 2 {
			detail["region"] = row[2]
		}
		if len(row) > 3 {
			detail["city"] = row[3]
		}
		record := recordFromPrefix(p, "relay", 100, detailJSON(detail))
		if len(row) > 1 {
			record.Country = strings.ToUpper(row[1])
		}
		out.Records = append(out.Records, record)
	}
	return out, nil
}

func parseOpenProxies(dir string, files []string) (parsedSource, error) {
	var out parsedSource
	f, err := os.Open(filepath.Join(dir, files[0]))
	if err != nil {
		return out, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw := line
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		addr, err := netip.ParseAddr(u.Hostname())
		if err != nil {
			continue
		}
		detail := map[string]any{"proxy": u.Scheme}
		if u.Port() != "" {
			detail["port"] = u.Port()
		}
		out.Records = append(out.Records, recordFromAddr(addr, "proxy", 70, detailJSON(detail)))
	}
	return out, sc.Err()
}

func parseAWS(dir string, files []string) (parsedSource, error) {
	var out parsedSource
	b, err := os.ReadFile(filepath.Join(dir, files[0]))
	if err != nil {
		return out, err
	}
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Region     string `json:"region"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return out, err
	}
	for _, p := range doc.Prefixes {
		if err := appendCloud(&out, p.IPPrefix, "aws", p.Service, p.Region, "hosting", 95); err != nil {
			return out, err
		}
	}
	for _, p := range doc.IPv6Prefixes {
		if err := appendCloud(&out, p.IPv6Prefix, "aws", p.Service, p.Region, "hosting", 95); err != nil {
			return out, err
		}
	}
	return out, nil
}

func parseGCP(dir string, files []string) (parsedSource, error) {
	var out parsedSource
	b, err := os.ReadFile(filepath.Join(dir, files[0]))
	if err != nil {
		return out, err
	}
	var doc struct {
		Prefixes []struct {
			IPv4    string `json:"ipv4Prefix"`
			IPv6    string `json:"ipv6Prefix"`
			Service string `json:"service"`
			Scope   string `json:"scope"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return out, err
	}
	for _, p := range doc.Prefixes {
		token := p.IPv4
		if token == "" {
			token = p.IPv6
		}
		if err := appendCloud(&out, token, "gcp", p.Service, p.Scope, "hosting", 95); err != nil {
			return out, err
		}
	}
	return out, nil
}

func parseOracle(dir string, files []string) (parsedSource, error) {
	var out parsedSource
	b, err := os.ReadFile(filepath.Join(dir, files[0]))
	if err != nil {
		return out, err
	}
	var doc struct {
		Regions []struct {
			Region string `json:"region"`
			CIDRs  []struct {
				CIDR string   `json:"cidr"`
				Tags []string `json:"tags"`
			} `json:"cidrs"`
		} `json:"regions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return out, err
	}
	for _, region := range doc.Regions {
		for _, c := range region.CIDRs {
			if err := appendCloud(&out, c.CIDR, "oracle", strings.Join(c.Tags, ","), region.Region, "hosting", 95); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

func parseDigitalOcean(dir string, files []string) (parsedSource, error) {
	return parseCSVFirstPrefix(dir, files[0], "digitalocean", "hosting", 95)
}

func parseLinode(dir string, files []string) (parsedSource, error) {
	return parseCSVFirstPrefix(dir, files[0], "linode", "hosting", 95)
}

func parseCSVFirstPrefix(dir, name, provider, category string, confidence uint8) (parsedSource, error) {
	var out parsedSource
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return out, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		first := strings.SplitN(line, ",", 2)[0]
		p, err := parsePrefix(first)
		if err != nil {
			continue
		}
		out.Records = append(out.Records, recordFromPrefix(p, category, confidence, detailJSON(map[string]any{"provider": provider})))
	}
	return out, sc.Err()
}

func parseFastly(dir string, files []string) (parsedSource, error) {
	var out parsedSource
	b, err := os.ReadFile(filepath.Join(dir, files[0]))
	if err != nil {
		return out, err
	}
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return out, err
	}
	for _, c := range append(doc.Addresses, doc.IPv6Addresses...) {
		if err := appendCloud(&out, c, "fastly", "cdn", "global", "cdn", 70); err != nil {
			return out, err
		}
	}
	return out, nil
}

func appendCloud(out *parsedSource, token, provider, service, region, category string, confidence uint8) error {
	if strings.TrimSpace(token) == "" {
		return nil
	}
	p, err := parsePrefix(token)
	if err != nil {
		return err
	}
	out.Records = append(out.Records, recordFromPrefix(p, category, confidence, detailJSON(map[string]any{
		"provider": provider, "service": service, "region": region,
	})))
	return nil
}
