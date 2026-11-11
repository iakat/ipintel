package ipintel

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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

type proxyAggregate struct {
	family     uint8
	start, end [16]byte
	roles      map[string]bool
	protocols  map[string]bool
	ports      map[string]bool
	sources    map[string]bool
	proxyHosts map[string]bool
	asn        uint32
	org        string
	country    string
}

type proxyParser struct {
	entries map[string]*proxyAggregate
	keys    []string
}

func newProxyParser() *proxyParser {
	return &proxyParser{entries: make(map[string]*proxyAggregate)}
}

func (p *proxyParser) add(addr netip.Addr, role, protocol, port, source, proxyHost string, asn uint32, org, country string) {
	if !addr.IsValid() {
		return
	}
	addr = addr.Unmap()
	family, start := addrBytes(addr)
	key := fmt.Sprintf("%d|%x|%x", family, start, start)
	e, ok := p.entries[key]
	if !ok {
		e = &proxyAggregate{
			family: family, start: start, end: start,
			roles:      map[string]bool{},
			protocols:  map[string]bool{},
			ports:      map[string]bool{},
			sources:    map[string]bool{},
			proxyHosts: map[string]bool{},
		}
		p.entries[key] = e
		p.keys = append(p.keys, key)
	}
	if role != "" {
		e.roles[role] = true
	}
	if protocol != "" {
		e.protocols[protocol] = true
	}
	if port != "" {
		e.ports[port] = true
	}
	if source != "" {
		e.sources[source] = true
	}
	if proxyHost != "" {
		e.proxyHosts[proxyHost] = true
	}
	if e.asn == 0 && asn != 0 {
		e.asn = asn
	}
	if e.org == "" && org != "" {
		e.org = org
	}
	if e.country == "" && country != "" {
		e.country = country
	}
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func (p *proxyParser) result() parsedSource {
	out := parsedSource{Records: make([]Record, 0, len(p.entries))}
	for _, key := range p.keys {
		e := p.entries[key]
		protocols := sortedSet(e.protocols)
		ports := sortedSet(e.ports)
		detail := map[string]any{
			"roles":     sortedSet(e.roles),
			"protocols": protocols,
			"ports":     ports,
			"sources":   sortedSet(e.sources),
		}
		if hosts := sortedSet(e.proxyHosts); len(hosts) > 0 {
			detail["proxy_hosts"] = hosts
		}
		if e.asn != 0 {
			detail["asn"] = e.asn
		}
		if e.org != "" {
			detail["org"] = e.org
		}
		if e.country != "" {
			detail["country"] = e.country
		}
		if len(protocols) > 0 {
			detail["proxy"] = protocols[0]
		}
		if len(ports) > 0 {
			detail["port"] = ports[0]
		}
		confidence := uint8(70)
		switch {
		case len(e.sources) >= 3:
			confidence = 85
		case len(e.sources) == 2:
			confidence = 80
		}
		out.Records = append(out.Records, Record{
			Family: e.family, Start: e.start, End: e.end,
			Category: "proxy", Confidence: confidence,
			ASN: e.asn, Org: e.org, Country: e.country,
			Detail: detailJSON(detail),
		})
	}
	return out
}

type monosansProxy struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	ExitIP   string `json:"exit_ip"`
	ASN      *struct {
		Number uint32 `json:"autonomous_system_number"`
		Org    string `json:"autonomous_system_organization"`
	} `json:"asn"`
	Geolocation struct {
		Country struct {
			ISOCode string `json:"iso_code"`
		} `json:"country"`
	} `json:"geolocation"`
}

func proxySourceLabel(name string) string {
	base := strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
	for _, label := range []string{"monosans", "clearproxy", "iplocate"} {
		if strings.Contains(base, label) {
			return label
		}
	}
	return base
}

func proxyProtocolHint(name string) string {
	switch {
	case strings.Contains(name, "socks4"):
		return "socks4"
	case strings.Contains(name, "socks5"):
		return "socks5"
	default:
		return "http"
	}
}

func parseOpenProxyJSON(path, name string, p *proxyParser) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rows []monosansProxy
	if err := json.Unmarshal(b, &rows); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	source := proxySourceLabel(name)
	for _, row := range rows {
		host, err := netip.ParseAddr(row.Host)
		if err != nil {
			continue
		}
		host = host.Unmap()
		protocol := row.Protocol
		if protocol == "" {
			protocol = "http"
		}
		port := ""
		if row.Port > 0 {
			port = strconv.Itoa(row.Port)
		}
		var asn uint32
		var org, country string
		if row.ASN != nil {
			asn, org = row.ASN.Number, row.ASN.Org
		}
		country = strings.ToUpper(strings.TrimSpace(row.Geolocation.Country.ISOCode))
		exit, exitErr := netip.ParseAddr(row.ExitIP)
		if exitErr == nil {
			exit = exit.Unmap()
		}
		if exitErr == nil && exit != host {
			p.add(host, "proxy_host", protocol, port, source, "", 0, "", "")
			p.add(exit, "exit", protocol, port, source, row.Host, asn, org, country)
			continue
		}
		p.add(host, "proxy", protocol, port, source, "", asn, org, country)
	}
	return nil
}

func parseOpenProxyText(path, name string, p *proxyParser) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	source := proxySourceLabel(name)
	hint := proxyProtocolHint(name)
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
		protocol := u.Scheme
		if !strings.Contains(line, "://") {
			protocol = hint
		}
		p.add(addr, "proxy", protocol, u.Port(), source, "", 0, "", "")
	}
	return sc.Err()
}

func parseOpenProxies(dir string, files []string) (parsedSource, error) {
	p := newProxyParser()
	for _, name := range files {
		path := filepath.Join(dir, name)
		var err error
		if strings.HasSuffix(strings.ToLower(name), ".json") {
			err = parseOpenProxyJSON(path, name, p)
		} else {
			err = parseOpenProxyText(path, name, p)
		}
		if err != nil {
			return parsedSource{}, err
		}
	}
	return p.result(), nil
}

func parseIPGeoVPN(dir string, files []string) (parsedSource, error) {
	var out parsedSource
	f, err := os.Open(filepath.Join(dir, files[0]))
	if err != nil {
		return out, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return out, err
	}
	defer zr.Close()
	r := csv.NewReader(zr)
	r.FieldsPerRecord = -1
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		if len(row) == 0 || strings.TrimSpace(row[0]) == "" {
			continue
		}
		p, err := parsePrefix(row[0])
		if err != nil {
			continue
		}
		detail := map[string]any{}
		if len(row) > 1 && strings.TrimSpace(row[1]) != "" {
			detail["provider"] = strings.TrimSpace(row[1])
		}
		if len(row) > 2 && strings.TrimSpace(row[2]) != "" {
			detail["basis"] = strings.TrimSpace(row[2])
		}
		out.Records = append(out.Records, recordFromPrefix(p, "vpn", 80, detailJSON(detail)))
	}
	return out, nil
}

func cloudCNProvider(name string) string {
	base := strings.TrimPrefix(filepath.Base(name), "cloud-cn-")
	for _, suffix := range []string{"-ipv4.txt", "-ipv6.txt"} {
		if strings.HasSuffix(base, suffix) {
			return strings.TrimSuffix(base, suffix)
		}
	}
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func parseCloudCN(dir string, files []string) (parsedSource, error) {
	var out parsedSource
	for _, name := range files {
		parsed, err := parseCIDRText(dir, []string{name}, "hosting", 90, map[string]any{
			"provider": cloudCNProvider(name),
			"list":     "axpwx",
		})
		if err != nil {
			return out, err
		}
		out.Records = append(out.Records, parsed.Records...)
	}
	return out, nil
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
