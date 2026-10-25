// Package ipintel builds and queries a compact, local IP-intelligence
// database. The database is a single file containing a sorted, deduplicated
// set of IP ranges from several public sources. Blocks are compressed with
// zstd; a small JSON index lets the query path touch only the blocks that can
// contain the requested address.
package ipintel

import (
	"encoding/json"
	"net/netip"
	"time"
)

const (
	FormatMagic   = "IPINTEL1"
	FormatVersion = 1
	headerSize    = 8 + 4 + 4 + 4 + 8 // magic, version, manifest len, index len, data offset
	DefaultBlock  = 512
)

// FileMeta describes one downloaded raw source file.
type FileMeta struct {
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	SHA256       string    `json:"sha256"`
	Bytes        int64     `json:"bytes"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	FetchedAt    time.Time `json:"fetched_at,omitempty"`
}

// SourceMeta describes one logical source. A source may consist of several
// files (for example X4B VPN IPv4 + IPv6 or a file per VPN provider).
type SourceMeta struct {
	ID       uint16     `json:"id"`
	Name     string     `json:"name"`
	Homepage string     `json:"homepage,omitempty"`
	License  string     `json:"license,omitempty"`
	Files    []FileMeta `json:"files,omitempty"`
	Records  int        `json:"records"`
	Optional bool       `json:"optional,omitempty"`
}

// Manifest is stored uncompressed at the start of the database. It is small
// (a few hundred kilobytes at most) and lets the service start without
// scanning the compressed blocks.
type Manifest struct {
	FormatVersion int               `json:"format_version"`
	BuiltAt       time.Time         `json:"built_at"`
	OpenASNBuild  string            `json:"openasn_build,omitempty"`
	RecordCount   int               `json:"record_count"`
	BlockCount    int               `json:"block_count"`
	BlockSize     int               `json:"block_size"`
	Sources       []SourceMeta      `json:"sources"`
	ASNs          map[uint32]string `json:"asns,omitempty"`
	Scoring       map[string]int    `json:"scoring,omitempty"`
}

// BlockHeader is the on-disk index entry for one zstd block.
type BlockHeader struct {
	Family       uint8  `json:"family"`
	FirstStart   string `json:"first_start"`
	MaxEnd       string `json:"max_end"`
	Count        int    `json:"count"`
	Offset       int64  `json:"offset"` // relative to the data section
	Compressed   int    `json:"compressed_size"`
	Uncompressed int    `json:"uncompressed_size"`
}

// Record is one normalized source entry. Start/End are always 16 bytes;
// IPv4 addresses occupy the first four bytes and the rest is zero.
type Record struct {
	Family     uint8
	Start      [16]byte
	End        [16]byte
	SourceID   uint16
	Category   string
	Confidence uint8
	ASN        uint32
	Org        string
	Country    string
	Detail     string // valid JSON object; kept verbatim for the query output
}

// Evidence is one source result for a queried IP.
type Evidence struct {
	Source     string          `json:"source"`
	Category   string          `json:"category,omitempty"`
	Confidence int             `json:"confidence,omitempty"`
	Matched    bool            `json:"matched"`
	Detail     json.RawMessage `json:"detail,omitempty"`
}

// CategoryScore shows the combined contribution of one category.
type CategoryScore struct {
	Category   string `json:"category"`
	Confidence int    `json:"confidence"`
	Score      int    `json:"score"`
}

// Result is the complete answer for one IP: the combined score plus every
// source result, including no-match sources where the caller asks for them.
type Result struct {
	IP         string          `json:"ip"`
	Country    string          `json:"country,omitempty"`
	ASN        uint32          `json:"asn,omitempty"`
	Org        string          `json:"org,omitempty"`
	Score      int             `json:"score"`
	Verdict    string          `json:"verdict"`
	Categories []CategoryScore `json:"categories,omitempty"`
	Evidence   []Evidence      `json:"evidence"`
	BuiltAt    time.Time       `json:"built_at,omitempty"`
	OpenASN    string          `json:"openasn_build,omitempty"`
}

// addrBytes normalizes an address into the 16-byte storage representation.
func addrBytes(a netip.Addr) (family uint8, out [16]byte) {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		copy(out[:4], b[:])
		return 4, out
	}
	return 6, a.As16()
}

// prefixRange returns the first and last address of a prefix in storage form.
func prefixRange(p netip.Prefix) (family uint8, start, end [16]byte) {
	p = p.Masked()
	a := p.Addr().Unmap()
	if !a.IsValid() {
		return 0, start, end
	}
	if a.Is4() {
		start = addr4(a)
		end = start
		hostBits := 32 - p.Bits()
		for i := 0; i < hostBits; i++ {
			end[3-i/8] |= 1 << (i % 8)
		}
		return 4, start, end
	}
	family, start = addrBytes(a)
	end = start
	hostBits := 128 - p.Bits()
	for i := 0; i < hostBits; i++ {
		end[15-i/8] |= 1 << (i % 8)
	}
	return family, start, end
}

func addr4(a netip.Addr) (out [16]byte) {
	b := a.As4()
	copy(out[:4], b[:])
	return out
}

func addrString(family uint8, b [16]byte) string {
	if family == 4 {
		return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}).String()
	}
	return netip.AddrFrom16(b).String()
}

func detailJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{}`
	}
	return string(b)
}
