package ipintel

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"sync"

	"github.com/klauspost/compress/zstd"
)

var newZstdReader = zstd.NewReader

type runtimeBlock struct {
	header BlockHeader
	family uint8
	first  [16]byte
	max    [16]byte
}

// DB is a read-only handle to one ipintel database.
type DB struct {
	f          *os.File
	data       []byte // non-nil when opened with OpenInMemory
	manifest   Manifest
	blocks     []runtimeBlock
	dataOffset int64
	decoder    *zstd.Decoder
	mu         sync.Mutex
}

// Open opens and validates a database.
func Open(path string) (*DB, error) {
	return open(path, false)
}

// OpenInMemory reads the whole database file into memory. The zstd blocks are
// still decompressed on demand, but all reads avoid the filesystem.
func OpenInMemory(path string) (*DB, error) {
	return open(path, true)
}

func open(path string, inMemory bool) (*DB, error) {
	var f *os.File
	var data []byte
	var reader io.Reader
	if inMemory {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		data = b
		reader = bytes.NewReader(b)
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		f = file
		reader = file
	}
	closeFile := func() {
		if f != nil {
			f.Close()
		}
	}
	hdr := make([]byte, headerSize)
	if _, err := io.ReadFull(reader, hdr); err != nil {
		closeFile()
		return nil, err
	}
	if string(hdr[:8]) != FormatMagic {
		closeFile()
		return nil, fmt.Errorf("not an ipintel database")
	}
	version := binary.LittleEndian.Uint32(hdr[8:12])
	if version != FormatVersion {
		closeFile()
		return nil, fmt.Errorf("unsupported format version %d", version)
	}
	manifestLen := binary.LittleEndian.Uint32(hdr[12:16])
	indexLen := binary.LittleEndian.Uint32(hdr[16:20])
	dataOffset := int64(binary.LittleEndian.Uint64(hdr[20:28]))
	if manifestLen > 64*1024*1024 || indexLen > 64*1024*1024 {
		closeFile()
		return nil, fmt.Errorf("invalid manifest/index size")
	}
	if dataOffset < int64(headerSize)+int64(manifestLen)+int64(indexLen) {
		closeFile()
		return nil, fmt.Errorf("invalid data offset")
	}
	manifestBytes := make([]byte, manifestLen)
	if _, err := io.ReadFull(reader, manifestBytes); err != nil {
		closeFile()
		return nil, err
	}
	indexBytes := make([]byte, indexLen)
	if _, err := io.ReadFull(reader, indexBytes); err != nil {
		closeFile()
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		closeFile()
		return nil, err
	}
	if manifest.FormatVersion != FormatVersion {
		closeFile()
		return nil, fmt.Errorf("manifest format version %d", manifest.FormatVersion)
	}
	var index []BlockHeader
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		closeFile()
		return nil, err
	}
	db := &DB{f: f, data: data, manifest: manifest, dataOffset: dataOffset}
	db.blocks = make([]runtimeBlock, 0, len(index))
	for _, h := range index {
		first, err := netip.ParseAddr(h.FirstStart)
		if err != nil {
			closeFile()
			return nil, fmt.Errorf("bad block first_start %q: %w", h.FirstStart, err)
		}
		maxEnd, err := netip.ParseAddr(h.MaxEnd)
		if err != nil {
			closeFile()
			return nil, fmt.Errorf("bad block max_end %q: %w", h.MaxEnd, err)
		}
		fam, firstBytes := addrBytes(first)
		_, maxBytes := addrBytes(maxEnd)
		if fam != h.Family {
			closeFile()
			return nil, fmt.Errorf("block family mismatch")
		}
		db.blocks = append(db.blocks, runtimeBlock{
			header: h, family: fam, first: firstBytes, max: maxBytes,
		})
	}
	dec, err := newZstdReader(nil)
	if err != nil {
		closeFile()
		return nil, err
	}
	db.decoder = dec
	return db, nil
}

// Close releases the file and decoder.
func (db *DB) Close() error {
	if db == nil {
		return nil
	}
	if db.decoder != nil {
		db.decoder.Close()
	}
	if db.f != nil {
		return db.f.Close()
	}
	return nil
}

// Manifest returns a copy of the database manifest.
func (db *DB) Manifest() Manifest {
	return db.manifest
}

// AllRecords decodes every block. It is intended for rebuilds and audits, not
// for the query path.
func (db *DB) AllRecords() ([]Record, error) {
	var out []Record
	for _, block := range db.blocks {
		records, err := db.readBlock(block)
		if err != nil {
			return nil, err
		}
		out = append(out, records...)
	}
	return out, nil
}

// Lookup returns the combined result and every source result for ip. Sources
// that did not match are included with Matched=false.
func (db *DB) Lookup(ip string) (Result, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return Result{}, fmt.Errorf("invalid IP %q: %w", ip, err)
	}
	a = a.Unmap()
	family, key := addrBytes(a)
	var evidence []Evidence
	seenEvidence := map[string]struct{}{}
	matchedSources := map[string]bool{}
	var country string
	var asn uint32
	var org string
	asnRank := 0

	for _, block := range db.blocks {
		if block.family != family {
			continue
		}
		if bytes.Compare(key[:], block.first[:]) < 0 {
			continue
		}
		if bytes.Compare(key[:], block.max[:]) > 0 {
			continue
		}
		records, err := db.readBlock(block)
		if err != nil {
			return Result{}, err
		}
		for _, r := range records {
			if r.Family != family {
				continue
			}
			if bytes.Compare(key[:], r.Start[:]) < 0 || bytes.Compare(key[:], r.End[:]) > 0 {
				continue
			}
			source := db.sourceName(r.SourceID)
			ev := Evidence{
				Source: source, Category: r.Category, Confidence: int(r.Confidence),
				Matched: true, Detail: rawDetail(r.Detail),
			}
			k := evidenceKey(ev)
			if _, ok := seenEvidence[k]; !ok {
				seenEvidence[k] = struct{}{}
				evidence = append(evidence, ev)
			}
			matchedSources[source] = true
			if country == "" && r.Country != "" {
				country = r.Country
			}
			if r.ASN != 0 {
				rank := 1
				if source == "openasn" {
					rank = 2
					if categoryWeights[r.Category] > 0 {
						rank = 3
					}
				}
				if rank > asnRank {
					asn, org, asnRank = r.ASN, r.Org, rank
				}
			}
		}
	}

	if asn != 0 {
		if entity, ok := db.manifest.ASNs[asn]; ok {
			ev := Evidence{
				Source: "bad-asn-list", Category: "hosting", Confidence: 60,
				Matched: true, Detail: rawJSON(map[string]any{"asn": asn, "entity": entity}),
			}
			k := evidenceKey(ev)
			if _, exists := seenEvidence[k]; !exists {
				seenEvidence[k] = struct{}{}
				evidence = append(evidence, ev)
			}
			matchedSources["bad-asn-list"] = true
		}
	}

	// Include one "no match" entry per source, so the answer is auditable even
	// when most lists are negative.
	for _, source := range db.manifest.Sources {
		if matchedSources[source.Name] {
			continue
		}
		if source.Name == "bad-asn-list" && asn == 0 {
			continue
		}
		evidence = append(evidence, Evidence{Source: source.Name, Matched: false})
	}

	sort.SliceStable(evidence, func(i, j int) bool {
		if evidence[i].Source != evidence[j].Source {
			return evidence[i].Source < evidence[j].Source
		}
		if evidence[i].Category != evidence[j].Category {
			return evidence[i].Category < evidence[j].Category
		}
		return evidence[i].Confidence > evidence[j].Confidence
	})
	score, verdict, categories := scoreEvidence(evidence)
	return Result{
		IP: a.String(), Country: country, ASN: asn, Org: org,
		Score: score, Verdict: verdict, Categories: categories,
		Evidence: evidence, BuiltAt: db.manifest.BuiltAt, OpenASN: db.manifest.OpenASNBuild,
	}, nil
}

func (db *DB) sourceName(id uint16) string {
	if int(id) < len(db.manifest.Sources) {
		return db.manifest.Sources[id].Name
	}
	return "source-" + strconv.Itoa(int(id))
}

func (db *DB) readBlock(b runtimeBlock) ([]Record, error) {
	if b.header.Compressed <= 0 || b.header.Compressed > 64*1024*1024 ||
		b.header.Uncompressed <= 0 || b.header.Uncompressed > 256*1024*1024 {
		return nil, fmt.Errorf("invalid block sizes")
	}
	var buf []byte
	if db.data != nil {
		start := db.dataOffset + b.header.Offset
		end := start + int64(b.header.Compressed)
		if start < 0 || end > int64(len(db.data)) {
			return nil, fmt.Errorf("block outside in-memory database")
		}
		buf = db.data[start:end]
	} else {
		buf = make([]byte, b.header.Compressed)
		if _, err := db.f.ReadAt(buf, db.dataOffset+b.header.Offset); err != nil {
			return nil, err
		}
	}
	db.mu.Lock()
	raw, err := db.decoder.DecodeAll(buf, nil)
	db.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if len(raw) != b.header.Uncompressed {
		return nil, fmt.Errorf("block size mismatch: got %d want %d", len(raw), b.header.Uncompressed)
	}
	return decodeRecords(raw)
}

func evidenceKey(e Evidence) string {
	return e.Source + "|" + e.Category + "|" + strconv.Itoa(e.Confidence) + "|" + string(e.Detail)
}

func rawDetail(s string) json.RawMessage {
	if s == "" {
		return nil
	}
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	return rawJSON(s)
}

func rawJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
