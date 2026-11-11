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
	Group    string
	Homepage string
	License  string
	Optional bool
	// Partial allows an optional source to build from the files that are
	// present instead of being skipped when one file is missing.
	Partial bool
	Files   []fetchFile
	Parse   func(dir string, files []string) (parsedSource, error)
}

type parsedSource struct {
	Records []Record
	ASNs    map[uint32]string
}

// sourceHomepages is the public credit/homepage for each source. Keep it in
// sync with the README source table.
var sourceHomepages = map[string]string{
	"openasn":                "https://github.com/openasn/openasn",
	"geolite2-country":       "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/",
	"geolite2-asn":           "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/",
	"x4b-vpn":                "https://github.com/X4BNet/lists_vpn",
	"x4b-datacenter":         "https://github.com/X4BNet/lists_vpn",
	"vpn-provider":           "https://github.com/Joe12387/open-source-vpn-ip-lists",
	"nazgul-vpn":             "https://github.com/NazgulCoder/IPLists",
	"pomerium-vpn":           "https://github.com/pomerium/vpnlist",
	"cloudflare-warp":        "https://github.com/NazgulCoder/IPLists",
	"bad-asn-list":           "https://github.com/brianhama/bad-asn-list",
	"tor-exit":               "https://check.torproject.org/torbulkexitlist",
	"icloud-relay":           "https://support.apple.com/en-us/102602",
	"aws":                    "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html",
	"gcp":                    "https://cloud.google.com/compute/docs/faq#find_ip_range",
	"cloudflare":             "https://www.cloudflare.com/ips/",
	"oracle":                 "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
	"digitalocean":           "https://www.digitalocean.com/geo/google.csv",
	"linode":                 "https://geoip.linode.com/",
	"fastly":                 "https://www.fastly.com/documentation/reference/api/utils/public-ip-list/",
	"open-proxies":           "https://github.com/monosans/proxy-list",
	"ipgeo-vpn":              "https://github.com/whois-api-llc/ipgeo-community",
	"hexydec-datacenter":     "https://github.com/hexydec/ip-ranges",
	"cloud-cn":               "https://github.com/axpwx/IP-Data",
	"googlebot":              "https://developers.google.com/crawling/docs/crawlers-fetchers/overview-google-crawlers",
	"google-special-crawler": "https://developers.google.com/crawling/docs/crawlers-fetchers/google-special-case-crawlers",
	"bingbot":                "https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0",
	"applebot":               "https://support.apple.com/en-us/HT204683",
	"gptbot":                 "https://platform.openai.com/docs/bots",
	"openai-searchbot":       "https://platform.openai.com/docs/bots",
	"chatgpt-user":           "https://platform.openai.com/docs/bots",
	"perplexitybot":          "https://docs.perplexity.ai/guides/bots",
	"ccbot":                  "https://commoncrawl.org/ccbot",
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
			Name: "open-proxies", License: "MIT", Optional: true, Partial: true,
			Files: []fetchFile{
				{Name: "open-proxies-monosans.json", URL: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json"},
				{Name: "open-proxies-clearproxy-http.txt", URL: "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/http/raw/all.txt"},
				{Name: "open-proxies-clearproxy-socks4.txt", URL: "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/socks4/raw/all.txt"},
				{Name: "open-proxies-clearproxy-socks5.txt", URL: "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/socks5/raw/all.txt"},
				{Name: "open-proxies-iplocate.txt", URL: "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt"},
			},
			Parse: parseOpenProxies,
		},
		sourceSpec{
			Name: "ipgeo-vpn", License: "CC BY-SA 4.0", Optional: true,
			Files: []fetchFile{{
				Name: "ipgeo-vpn.csv.gz",
				URL:  "https://github.com/whois-api-llc/ipgeo-community/releases/latest/download/community-vpn-list.csv.gz",
			}},
			Parse: parseIPGeoVPN,
		},
		sourceSpec{
			Name: "hexydec-datacenter", License: "MIT", Optional: true, Partial: true,
			Files: []fetchFile{
				{Name: "hexydec-datacentres-ipv4.txt", URL: "https://raw.githubusercontent.com/hexydec/ip-ranges/main/output/datacentres-ipv4.txt"},
				{Name: "hexydec-datacentres-ipv6.txt", URL: "https://raw.githubusercontent.com/hexydec/ip-ranges/main/output/datacentres-ipv6.txt"},
			},
			Parse: func(dir string, files []string) (parsedSource, error) {
				return parseCIDRText(dir, files, "hosting", 80, map[string]any{"list": "hexydec-datacentres"})
			},
		},
		sourceSpec{
			Name: "cloud-cn", License: "MIT", Optional: true, Partial: true,
			Files: []fetchFile{
				{Name: "cloud-cn-aliyun-ipv4.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/aliyun-cidr-ipv4.txt"},
				{Name: "cloud-cn-aliyun-ipv6.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/aliyun-cidr-ipv6.txt"},
				{Name: "cloud-cn-baidu-ipv4.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/baidu-cidr-ipv4.txt"},
				{Name: "cloud-cn-baidu-ipv6.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/baidu-cidr-ipv6.txt"},
				{Name: "cloud-cn-huawei-ipv4.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/huawei-cidr-ipv4.txt"},
				{Name: "cloud-cn-huawei-ipv6.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/huawei-cidr-ipv6.txt"},
				{Name: "cloud-cn-jdcloud-ipv4.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/jdcloud-cidr-ipv4.txt"},
				{Name: "cloud-cn-jdcloud-ipv6.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/jdcloud-cidr-ipv6.txt"},
				{Name: "cloud-cn-ksyun-ipv4.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/ksyun-cidr-ipv4.txt"},
				{Name: "cloud-cn-ksyun-ipv6.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/ksyun-cidr-ipv6.txt"},
				{Name: "cloud-cn-tencent-ipv4.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/tencent-cidr-ipv4.txt"},
				{Name: "cloud-cn-tencent-ipv6.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/tencent-cidr-ipv6.txt"},
				{Name: "cloud-cn-ucloud-ipv4.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/ucloud-cidr-ipv4.txt"},
				{Name: "cloud-cn-ucloud-ipv6.txt", URL: "https://raw.githubusercontent.com/axpwx/IP-Data/master/provider/ucloud-cidr-ipv6.txt"},
			},
			Parse: parseCloudCN,
		},
	)

	// Crawler ranges are published by the operators themselves. They are
	// evidence only: the category weight is 0, so a crawler match never
	// changes the score or the verdict. Grouping and per-bot detail let a
	// caller allow known crawlers without treating AI crawlers the same as
	// search crawlers.
	specs = append(specs, crawlerSpecs()...)

	for i := range specs {
		specs[i].Homepage = sourceHomepages[specs[i].Name]
	}
	out := specs[:0]
	for _, spec := range specs {
		if opts.Exclude[spec.Name] {
			continue
		}
		// A group name disables every source in that group.
		if spec.Group != "" && opts.Exclude[spec.Group] {
			continue
		}
		out = append(out, spec)
	}
	return out
}

// crawlerSpecs returns the vendor-published crawler and fetcher ranges. Every
// source is optional so a retired feed cannot break a build. The category
// (search_crawler or ai_crawler) carries no score weight; the group only marks
// the sources as crawler lists.
func crawlerSpecs() []sourceSpec {
	group := "crawlers"
	return []sourceSpec{
		{
			Name: "googlebot", Group: group, Optional: true,
			License: "Google crawler IP ranges (public)",
			Files: []fetchFile{{
				Name: "googlebot-common.json",
				URL:  "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
			}},
			Parse: parseBotRanges("search_crawler", "Google", "Googlebot"),
		},
		{
			Name: "google-special-crawler", Group: group, Optional: true,
			License: "Google crawler IP ranges (public)",
			Files: []fetchFile{{
				Name: "googlebot-special.json",
				URL:  "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
			}},
			Parse: parseBotRanges("search_crawler", "Google", "AdsBot/Mediapartners"),
		},
		{
			Name: "bingbot", Group: group, Optional: true,
			License: "Bing crawler IP ranges (public)",
			Files: []fetchFile{{
				Name: "bingbot.json",
				URL:  "https://www.bing.com/toolbox/bingbot.json",
			}},
			Parse: parseBotRanges("search_crawler", "Microsoft", "Bingbot"),
		},
		{
			Name: "applebot", Group: group, Optional: true,
			License: "Apple crawler IP ranges (public)",
			Files: []fetchFile{{
				Name: "applebot.json",
				URL:  "https://search.developer.apple.com/applebot.json",
			}},
			Parse: parseBotRanges("search_crawler", "Apple", "Applebot"),
		},
		{
			Name: "gptbot", Group: group, Optional: true,
			License: "OpenAI crawler IP ranges (public)",
			Files: []fetchFile{{
				Name: "gptbot.json",
				URL:  "https://openai.com/gptbot.json",
			}},
			Parse: parseBotRanges("ai_crawler", "OpenAI", "GPTBot"),
		},
		{
			Name: "openai-searchbot", Group: group, Optional: true,
			License: "OpenAI crawler IP ranges (public)",
			Files: []fetchFile{{
				Name: "openai-searchbot.json",
				URL:  "https://openai.com/searchbot.json",
			}},
			Parse: parseBotRanges("ai_crawler", "OpenAI", "OAI-SearchBot"),
		},
		{
			Name: "chatgpt-user", Group: group, Optional: true,
			License: "OpenAI fetcher IP ranges (public)",
			Files: []fetchFile{{
				Name: "chatgpt-user.json",
				URL:  "https://openai.com/chatgpt-user.json",
			}},
			Parse: parseBotRanges("ai_crawler", "OpenAI", "ChatGPT-User"),
		},
		{
			Name: "perplexitybot", Group: group, Optional: true,
			License: "Perplexity crawler IP ranges (public)",
			Files: []fetchFile{{
				Name: "perplexitybot.json",
				URL:  "https://www.perplexity.ai/perplexitybot.json",
			}},
			Parse: parseBotRanges("ai_crawler", "Perplexity", "PerplexityBot"),
		},
		{
			Name: "ccbot", Group: group, Optional: true,
			License: "Common Crawl crawler IP ranges (public)",
			Files: []fetchFile{{
				Name: "ccbot.json",
				URL:  "https://index.commoncrawl.org/ccbot.json",
			}},
			Parse: parseBotRanges("ai_crawler", "Common Crawl", "CCBot"),
		},
	}
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

// SourceGroups returns the group names that --exclude also accepts, in the
// order they first appear in the source list.
func SourceGroups() []string {
	specs := sourceSpecs(Options{})
	seen := make(map[string]bool, len(specs))
	groups := make([]string, 0, 4)
	for _, spec := range specs {
		if spec.Group == "" || seen[spec.Group] {
			continue
		}
		seen[spec.Group] = true
		groups = append(groups, spec.Group)
	}
	return groups
}
