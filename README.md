# ip-intel

Small standalone service and Go library for local IP intelligence.

It downloads public static lists, normalizes them into one sorted/deduplicated
database, compresses each block with zstd, and answers a lookup from a small
uncompressed block index. No end-user IP is sent to a third party.

## Install

```bash
go install github.com/iakat/ipintel/cmd/ip-intel@latest
```

## Build the database

All sources are enabled by default. `--exclude` is repeatable and also accepts
comma-separated names; `ip-intel sources` prints the accepted names.

```bash
# download everything (OpenASN, GeoLite2, X4B, VPN lists, Tor, iCloud Relay,
# cloud ranges, open proxies) and build data/ipintel.bin
go run ./cmd/ip-intel fetch --out data

# leave out a few sources
go run ./cmd/ip-intel fetch --out data \
  --exclude open-proxies,cloudflare-warp

# incremental update: HEAD each source, download only changed files, and
# reuse the old DB records for sources whose raw file is absent/unchanged
go run ./cmd/ip-intel fetch --out data --update --parallel 8

# rebuild from an existing raw directory, optionally reusing a base DB
go run ./cmd/ip-intel build \
  --raw data/raw --db data/ipintel.bin --base-db data/ipintel.bin

# list selectable source names
go run ./cmd/ip-intel sources
```

The `data/` directory is local and ignored by git; neither the downloaded raw
lists nor the built `ipintel.bin` are committed.

`fetch` is idempotent: it sends a `HEAD` request first and skips a file when
its `ETag` or `Last-Modified` matches the sidecar in `data/raw/.meta/`. Servers
without validators fall back to conditional `GET` / size checks. Downloads run
in parallel (`--parallel`, default 6).

`fetch --update` also uses the validators in the existing `ipintel.bin`
manifest. If a raw file is missing but its source is unchanged, the old
records are carried forward from the database; only changed sources are
downloaded and reparsed. That means you can delete the large raw files after a
build and still update incrementally, as long as `ipintel.bin` is kept.

## Query

```bash
go run ./cmd/ip-intel query --db data/ipintel.bin 8.8.8.8
go run ./cmd/ip-intel query --db data/ipintel.bin --in-memory 1.1.1.1 2001:db8::1
```

`--in-memory` reads the whole compressed database once; lookups still
decompress only candidate blocks.

The JSON contains:

- `score` and `verdict` (a confidence-weighted network score, not an abuse
  verdict);
- every source result, including `matched: false`;
- the raw detail object for each match.

## Service

```bash
go run ./cmd/ip-intel serve --db data/ipintel.bin --addr :8080 --in-memory
```

Endpoints:

- `GET /healthz`
- `GET /v1/lookup?ip=8.8.8.8`
- `GET /v1/lookup/8.8.8.8`
- `GET /v1/sources`
- `GET /v1/manifest`

`--reload 1m` checks the database mtime and swaps in a rebuilt file atomically.
Set `IPINTEL_DB` and `IPINTEL_ADDR` instead of flags if preferred.

## Library

The module exposes `github.com/iakat/ipintel/ipintel`:

```go
import "github.com/iakat/ipintel/ipintel"

db, err := ipintel.Open("data/ipintel.bin")
if err != nil {
    return err
}
defer db.Close()
res, err := db.Lookup("8.8.8.8")
```

Rastrelliera depends on this module from GitHub and loads the database when
`IPINTEL_DB` is set. The feature is optional: an unset or unreadable path simply
disables the admin badges and `/admin/ip`.

## Tests

```bash
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

The test suite enforces 100% statement coverage, including the CLI.
The GitHub Actions workflow runs `go vet`, the tests, and the coverage gate.

## Source credits

All sources are enabled by default. `--exclude` accepts the source name shown
below; `ip-intel sources` prints the same list. The exact feed URL for every
downloaded file is also recorded in the database manifest.

| Source (`--exclude`) | Used for | Credit | License / terms |
|---|---|---|---|
| `openasn` | ASN network type: residential, mobile, hosting, VPN, Tor, relay, business | [OpenASN](https://github.com/openasn/openasn) ([upstream attribution](https://github.com/openasn/openasn/blob/main/ATTRIBUTION.md)) | [CC0-1.0 data](https://github.com/openasn/openasn/blob/main/LICENSE-DATA), [MIT code](https://github.com/openasn/openasn/blob/main/LICENSE-CODE) |
| `geolite2-country` | Country | [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/), fetched via [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) | [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula), [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |
| `geolite2-asn` | ASN and organisation | [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/), fetched via [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) | [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula), [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |
| `x4b-vpn` | VPN netblocks | [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) | [MIT](https://github.com/X4BNet/lists_vpn#license) |
| `x4b-datacenter` | Datacenter and hosting ranges | [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) | [MIT](https://github.com/X4BNet/lists_vpn#license) |
| `vpn-provider` | First-party VPN server/egress IPs | [Joe12387/open-source-vpn-ip-lists](https://github.com/Joe12387/open-source-vpn-ip-lists) | [CC0-1.0](https://github.com/Joe12387/open-source-vpn-ip-lists/blob/main/LICENSE) |
| `nazgul-vpn` | VPN IPv4 and IPv6 ranges | [NazgulCoder/IPLists](https://github.com/NazgulCoder/IPLists) | [MIT](https://github.com/NazgulCoder/IPLists/blob/main/LICENSE) |
| `pomerium-vpn` | VPN candidates, zero scoring weight | [pomerium/vpnlist](https://github.com/pomerium/vpnlist) | [Apache-2.0](https://github.com/pomerium/vpnlist/blob/main/LICENSE) |
| `cloudflare-warp` | Cloudflare WARP ranges | [NazgulCoder/IPLists](https://github.com/NazgulCoder/IPLists/blob/main/resources/cloudflare-warp.txt), [Cloudflare WARP](https://developers.cloudflare.com/warp-client/) | [MIT](https://github.com/NazgulCoder/IPLists/blob/main/LICENSE) |
| `bad-asn-list` | Cloud, hosting and colo ASNs | [brianhama/bad-asn-list](https://github.com/brianhama/bad-asn-list) | [MIT](https://github.com/brianhama/bad-asn-list/blob/main/LICENSE) |
| `tor-exit` | Tor exit relays | [Tor Project bulk exit list](https://check.torproject.org/torbulkexitlist) | [Tor Project](https://www.torproject.org/) public list |
| `icloud-relay` | iCloud Private Relay egress ranges | [Apple: About iCloud Private Relay](https://support.apple.com/en-us/102602), [egress feed](https://mask-api.icloud.com/egress-ip-ranges.csv) | Apple public list, [Apple terms](https://www.apple.com/legal/internet-services/) |
| `aws` | AWS public IP ranges | [AWS IP address ranges](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html) | [AWS service terms](https://aws.amazon.com/service-terms/) |
| `gcp` | Google Cloud public IP ranges | [Google Cloud IP ranges](https://cloud.google.com/compute/docs/faq#find_ip_range) | [Google Cloud terms](https://cloud.google.com/terms) |
| `cloudflare` | Cloudflare CDN ranges | [Cloudflare IP ranges](https://www.cloudflare.com/ips/) | [Cloudflare terms](https://www.cloudflare.com/website-terms/) |
| `oracle` | Oracle Cloud public IP ranges | [Oracle public IP ranges](https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json) | [Oracle terms](https://www.oracle.com/legal/terms/) |
| `digitalocean` | DigitalOcean public geofeed | [DigitalOcean geofeed](https://www.digitalocean.com/geo/google.csv) | [DigitalOcean terms](https://www.digitalocean.com/legal/terms-of-service-agreement) |
| `linode` | Akamai/Linode public geofeed | [geoip.linode.com](https://geoip.linode.com/) | [Akamai/Linode terms](https://www.akamai.com/legal) |
| `fastly` | Fastly public IP ranges | [Fastly public IP list](https://www.fastly.com/documentation/reference/api/utils/public-ip-list/) | [Fastly terms](https://www.fastly.com/terms) |
| `open-proxies` | Open HTTP, SOCKS4 and SOCKS5 proxies | [monosans/proxy-list](https://github.com/monosans/proxy-list) | [MIT](https://github.com/monosans/proxy-list/blob/main/LICENSE) |

`vpn-provider` currently contains first-party lists for
[AirVPN](https://airvpn.org/), [IVPN](https://www.ivpn.net/),
[Mullvad](https://mullvad.net/), [NordVPN](https://nordvpn.com/),
[OVPN](https://www.ovpn.com/),
[Private Internet Access](https://www.privateinternetaccess.com/),
[ProtonVPN](https://protonvpn.com/), [RiseupVPN](https://riseup.net/en/vpn),
[Surfshark](https://surfshark.com/) and [Windscribe](https://windscribe.com/).

OpenASN compiles upstream ASN and overlay data; its attribution receipts are in
[ATTRIBUTION.md](https://github.com/openasn/openasn/blob/main/ATTRIBUTION.md).
GeoLite2 is fetched through the P3TERX mirror; the data remains MaxMind's and
the GeoLite2 EULA applies. The `aws`, `gcp`, `cloudflare`, `oracle`,
`digitalocean`, `linode`, `fastly` and `open-proxies` sources are marked
optional in the manifest: missing files do not fail a build, but they are
enabled by default.

`x4b` and the provider lists already cover much of the cloud/hosting space;
the cloud ranges add names and more precise prefixes. Cloudflare is tagged as
CDN, not as a VPN. Pomerium is tagged `vpn_candidate` and deliberately
contributes zero weight because its broad list produces false positives (for
example 8.8.8.0/24).

There is no free, reliable local residential-proxy dataset. OpenASN's
`residential_isp` verdict means an ordinary eyeball ISP, not a residential
proxy; the latter needs a commercial feed.

## License

The code is licensed under the [MIT License](LICENSE). Fetched data sources keep
their own licenses; see the source list and the `license` metadata in the
database manifest.
