package ipintel

// Options selects sources. All sources are enabled by default; Exclude is the
// set of source names to leave out.
type Options struct {
	Exclude map[string]bool
}

type fetchFile struct {
	Name string
	URL  string
}

type sourceSpec struct {
	Name     string
	Homepage string
	License  string
	Optional bool
	Files    []fetchFile
	Parse    func(dir string, files []string) (parsedSource, error)
}

type parsedSource struct {
	Records []Record
	ASNs    map[uint32]string
}

// sourceHomepages is the public credit/homepage for each source. Keep it in
// sync with the README source table.
var sourceHomepages = map[string]string{
	"openasn":          "https://github.com/openasn/openasn",
	"geolite2-country": "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/",
	"geolite2-asn":     "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/",
	"x4b-vpn":          "https://github.com/X4BNet/lists_vpn",
	"x4b-datacenter":   "https://github.com/X4BNet/lists_vpn",
	"vpn-provider":     "https://github.com/Joe12387/open-source-vpn-ip-lists",
	"nazgul-vpn":       "https://github.com/NazgulCoder/IPLists",
	"pomerium-vpn":     "https://github.com/pomerium/vpnlist",
	"cloudflare-warp":  "https://github.com/NazgulCoder/IPLists",
	"bad-asn-list":     "https://github.com/brianhama/bad-asn-list",
	"tor-exit":         "https://check.torproject.org/torbulkexitlist",
	"icloud-relay":     "https://support.apple.com/en-us/102602",
	"aws":              "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html",
	"gcp":              "https://cloud.google.com/compute/docs/faq#find_ip_range",
	"cloudflare":       "https://www.cloudflare.com/ips/",
	"oracle":           "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
	"digitalocean":     "https://www.digitalocean.com/geo/google.csv",
	"linode":           "https://geoip.linode.com/",
	"fastly":           "https://www.fastly.com/documentation/reference/api/utils/public-ip-list/",
	"open-proxies":     "https://github.com/monosans/proxy-list",
}

// sourceSpecs is the single source of truth for URLs, raw file names and
// parsers. Fetch and Build both use it so the raw directory stays portable.
func sourceSpecs(opts Options) []sourceSpec {
	providers := []string{
		"airvpn", "ivpn", "mullvad", "nordvpn", "ovpn",
		"pia", "protonvpn", "riseupvpn", "surfshark", "windscribe",
	}
	providerFiles := make([]fetchFile, 0, len(providers))
	for _, p := range providers {
		providerFiles = append(providerFiles, fetchFile{
			Name: "vpn-provider-" + p + ".txt",
			URL:  "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/" + p + ".txt",
		})
	}

	specs := []sourceSpec{
		{
			Name:    "openasn",
			License: "CC0-1.0 (data), MIT (code)",
			Files: []fetchFile{
				{Name: "openasn.mmdb", URL: "https://github.com/openasn/openasn/releases/download/latest/openasn.mmdb"},
				{Name: "openasn-build.json", URL: "https://github.com/openasn/openasn/releases/download/latest/manifest.json"},
				{Name: "openasn-checksums.txt", URL: "https://github.com/openasn/openasn/releases/download/latest/SHA256SUMS"},
			},
			Parse: parseOpenASN,
		},
		{
			Name:    "geolite2-country",
			License: "MaxMind GeoLite2 EULA",
			Files: []fetchFile{
				{Name: "GeoLite2-Country.mmdb", URL: "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"},
			},
			Parse: parseGeoLiteCountry,
		},
		{
			Name:    "geolite2-asn",
			License: "MaxMind GeoLite2 EULA",
			Files: []fetchFile{
				{Name: "GeoLite2-ASN.mmdb", URL: "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"},
			},
			Parse: parseGeoLiteASN,
		},
		{
			Name:    "x4b-vpn",
			License: "MIT",
			Files: []fetchFile{
				{Name: "vpn-ipv4.txt", URL: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"},
				{Name: "vpn-ipv6.txt", URL: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt"},
			},
			Parse: func(dir string, files []string) (parsedSource, error) {
				return parseCIDRText(dir, files, "vpn", 85, map[string]any{"list": "x4b-vpn"})
			},
		},
		{
			Name:    "x4b-datacenter",
			License: "MIT",
			Files: []fetchFile{
				{Name: "datacenter-ipv4.txt", URL: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"},
				{Name: "datacenter-ipv6.txt", URL: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt"},
			},
			Parse: func(dir string, files []string) (parsedSource, error) {
				return parseCIDRText(dir, files, "hosting", 80, map[string]any{"list": "x4b-datacenter"})
			},
		},
		{
			Name:    "vpn-provider",
			License: "CC0-1.0",
			Files:   providerFiles,
			Parse:   parseProviderIPs,
		},
		{
			Name:    "nazgul-vpn",
			License: "MIT",
			Files: []fetchFile{
				{Name: "vpn-nazgul-ipv4.txt", URL: "https://raw.githubusercontent.com/NazgulCoder/IPLists/main/output/vpn-ipv4.txt"},
				{Name: "vpn-nazgul-ipv6.txt", URL: "https://raw.githubusercontent.com/NazgulCoder/IPLists/main/output/vpn-ipv6.txt"},
			},
			Parse: func(dir string, files []string) (parsedSource, error) {
				return parseCIDRText(dir, files, "vpn", 65, map[string]any{"list": "nazgul"})
			},
		},
		{
			Name:    "pomerium-vpn",
			License: "Apache-2.0",
			Files: []fetchFile{
				{Name: "vpn-pomerium.json", URL: "https://raw.githubusercontent.com/pomerium/vpnlist/main/vpnlist.json"},
			},
			Parse: parsePomerium,
		},
		{
			Name:    "cloudflare-warp",
			License: "MIT",
			Files: []fetchFile{
				{Name: "cloudflare-warp.txt", URL: "https://raw.githubusercontent.com/NazgulCoder/IPLists/main/resources/cloudflare-warp.txt"},
			},
			Parse: func(dir string, files []string) (parsedSource, error) {
				return parseCIDRText(dir, files, "vpn", 70, map[string]any{"list": "cloudflare-warp"})
			},
		},
		{
			Name:    "bad-asn-list",
			License: "MIT",
			Files: []fetchFile{
				{Name: "bad-asn-list.csv", URL: "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv"},
			},
			Parse: parseBadASN,
		},
		{
			Name:    "tor-exit",
			License: "Tor Project public list",
			Files: []fetchFile{
				{Name: "tor-exits.txt", URL: "https://check.torproject.org/torbulkexitlist"},
			},
			Parse: parseIPFile("tor", 100, map[string]any{"tor_exit": true}),
		},
		{
			Name:    "icloud-relay",
			License: "Apple public egress list",
			Files: []fetchFile{
				{Name: "icloud-relay.csv", URL: "https://mask-api.icloud.com/egress-ip-ranges.csv"},
			},
			Parse: parseICloudRelay,
		},
	}

	specs = append(specs,
		sourceSpec{
			Name: "aws", License: "AWS public IP ranges", Optional: true,
			Files: []fetchFile{{Name: "aws-ip-ranges.json", URL: "https://ip-ranges.amazonaws.com/ip-ranges.json"}},
			Parse: parseAWS,
		},
		sourceSpec{
			Name: "gcp", License: "Google Cloud public IP ranges", Optional: true,
			Files: []fetchFile{{Name: "gcp-cloud.json", URL: "https://www.gstatic.com/ipranges/cloud.json"}},
			Parse: parseGCP,
		},
		sourceSpec{
			Name: "cloudflare", License: "Cloudflare public IP ranges", Optional: true,
			Files: []fetchFile{
				{Name: "cloudflare-ipv4.txt", URL: "https://www.cloudflare.com/ips-v4"},
				{Name: "cloudflare-ipv6.txt", URL: "https://www.cloudflare.com/ips-v6"},
			},
			Parse: func(dir string, files []string) (parsedSource, error) {
				return parseCIDRText(dir, files, "cdn", 70, map[string]any{"provider": "Cloudflare"})
			},
		},
		sourceSpec{
			Name: "oracle", License: "Oracle public IP ranges", Optional: true,
			Files: []fetchFile{{Name: "oracle-ip-ranges.json", URL: "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"}},
			Parse: parseOracle,
		},
		sourceSpec{
			Name: "digitalocean", License: "DigitalOcean public geofeed", Optional: true,
			Files: []fetchFile{{Name: "digitalocean-ip-ranges.csv", URL: "https://digitalocean.com/geo/google.csv"}},
			Parse: parseDigitalOcean,
		},
		sourceSpec{
			Name: "linode", License: "Akamai/Linode public geofeed", Optional: true,
			Files: []fetchFile{{Name: "linode-ip-ranges.csv", URL: "https://geoip.linode.com/"}},
			Parse: parseLinode,
		},
		sourceSpec{
			Name: "fastly", License: "Fastly public IP list", Optional: true,
			Files: []fetchFile{{Name: "fastly-ip-ranges.json", URL: "https://api.fastly.com/public-ip-list"}},
			Parse: parseFastly,
		},
		sourceSpec{
			Name: "open-proxies", License: "MIT", Optional: true,
			Files: []fetchFile{{Name: "open-proxies.txt", URL: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt"}},
			Parse: parseOpenProxies,
		},
	)

	for i := range specs {
		specs[i].Homepage = sourceHomepages[specs[i].Name]
	}
	out := specs[:0]
	for _, spec := range specs {
		if opts.Exclude[spec.Name] {
			continue
		}
		out = append(out, spec)
	}
	return out
}

// SourceNames returns every selectable source name, including optional ones.
func SourceNames() []string {
	specs := sourceSpecs(Options{})
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.Name)
	}
	return names
}
