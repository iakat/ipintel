package ipintel

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"
)

// BuildOptions controls Build.
type BuildOptions struct {
	RawDir    string
	OutFile   string
	BaseDB    string
	Exclude   map[string]bool
	BlockSize int
}

type tempFile interface {
	io.Reader
	io.Writer
	io.Seeker
	Sync() error
	Close() error
}

var (
	createTemp = func(dir, pattern string) (tempFile, string, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, "", err
		}
		return f, f.Name(), nil
	}
	renameFile    = os.Rename
	marshalJSON   = json.Marshal
	newZstdWriter = zstd.NewWriter
)

// Build parses the raw directory, deduplicates and sorts every source entry,
// and writes the compressed database.
func Build(opts BuildOptions) (*Manifest, error) {
	if opts.BlockSize <= 0 {
		opts.BlockSize = DefaultBlock
	}
	specs := sourceSpecs(Options{Exclude: opts.Exclude})

	baseRecords, baseSources, baseASNs, baseBuildID, err := loadBase(opts.BaseDB)
	if err != nil {
		return nil, err
	}
	var records []Record
	var sources []SourceMeta
	asns := map[uint32]string{}
	seen := make(map[string]struct{})
	buildID := readOpenASNBuildID(opts.RawDir)
	if buildID == "" {
		buildID = baseBuildID
	}

	for _, spec := range specs {
		files, ok, err := sourceFiles(opts.RawDir, spec)
		if err != nil {
			return nil, err
		}
		if !ok {
			old, exists := baseRecords[spec.Name]
			if !exists {
				if spec.Optional {
					continue
				}
				return nil, fmt.Errorf("source %s: missing files and no base records", spec.Name)
			}
			id := uint16(len(sources))
			for i := range old {
				old[i].SourceID = id
				key := recordKey(old[i])
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				records = append(records, old[i])
			}
			meta := baseSources[spec.Name]
			meta.ID, meta.Records, meta.Optional = id, len(old), spec.Optional
			meta.Homepage, meta.License = spec.Homepage, spec.License
			sources = append(sources, meta)
			if spec.Name == "bad-asn-list" {
				for asn, entity := range baseASNs {
					asns[asn] = entity
				}
			}
			continue
		}
		names := make([]string, 0, len(files))
		for _, f := range files {
			names = append(names, f.Name)
		}
		parsed, err := spec.Parse(opts.RawDir, names)
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", spec.Name, err)
		}
		id := uint16(len(sources))
		for i := range parsed.Records {
			parsed.Records[i].SourceID = id
			key := recordKey(parsed.Records[i])
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			records = append(records, parsed.Records[i])
		}
		for asn, entity := range parsed.ASNs {
			asns[asn] = entity
		}
		sources = append(sources, SourceMeta{
			ID: id, Name: spec.Name, Homepage: spec.Homepage, License: spec.License,
			Files: files, Records: len(parsed.Records) + len(parsed.ASNs),
			Optional: spec.Optional,
		})
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no records parsed")
	}
	sortRecords(records)
	manifest := &Manifest{
		FormatVersion: FormatVersion,
		BuiltAt:       time.Now().UTC(),
		OpenASNBuild:  buildID,
		RecordCount:   len(records),
		BlockSize:     opts.BlockSize,
		Sources:       sources,
		ASNs:          asns,
		Scoring:       scoringWeights(),
	}
	if err := writeDatabase(opts.OutFile, records, manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func loadBase(path string) (map[string][]Record, map[string]SourceMeta, map[uint32]string, string, error) {
	if path == "" {
		return nil, nil, nil, "", nil
	}
	db, err := Open(path)
	if err != nil {
		return nil, nil, nil, "", err
	}
	defer db.Close()
	all, err := db.AllRecords()
	if err != nil {
		return nil, nil, nil, "", err
	}
	records := make(map[string][]Record)
	for _, r := range all {
		name := db.sourceName(r.SourceID)
		r.SourceID = 0
		records[name] = append(records[name], r)
	}
	sources := make(map[string]SourceMeta, len(db.manifest.Sources))
	for _, s := range db.manifest.Sources {
		sources[s.Name] = s
	}
	return records, sources, db.manifest.ASNs, db.manifest.OpenASNBuild, nil
}

func sourceFiles(rawDir string, spec sourceSpec) ([]FileMeta, bool, error) {
	files := make([]FileMeta, 0, len(spec.Files))
	present := 0
	for _, f := range spec.Files {
		path := filepath.Join(rawDir, f.Name)
		st, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, false, err
		}
		hash, err := sha256File(path)
		if err != nil {
			return nil, false, err
		}
		meta := FileMeta{Name: f.Name, URL: f.URL, SHA256: hash, Bytes: st.Size()}
		if state, err := readFileState(filepath.Join(rawDir, ".meta", f.Name+".json")); err == nil && state.URL == f.URL {
			meta.ETag, meta.LastModified, meta.FetchedAt = state.ETag, state.LastModified, state.FetchedAt
		}
		files = append(files, meta)
		present++
	}
	if present == 0 {
		return nil, false, nil
	}
	if present != len(spec.Files) {
		if spec.Optional {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("source %s: incomplete files (%d/%d)", spec.Name, present, len(spec.Files))
	}
	return files, true, nil
}

func readOpenASNBuildID(rawDir string) string {
	b, err := os.ReadFile(filepath.Join(rawDir, "openasn-build.json"))
	if err != nil {
		return ""
	}
	var doc struct {
		BuildID string `json:"build_id"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return ""
	}
	return doc.BuildID
}

func recordKey(r Record) string {
	return fmt.Sprintf("%d|%x|%x|%d|%s|%d|%d|%s|%s|%s",
		r.Family, r.Start, r.End, r.SourceID, r.Category, r.Confidence,
		r.ASN, r.Org, r.Country, r.Detail)
}

func sortRecords(records []Record) {
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if c := bytes.Compare(a.Start[:], b.Start[:]); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(a.End[:], b.End[:]); c != 0 {
			return c < 0
		}
		if a.SourceID != b.SourceID {
			return a.SourceID < b.SourceID
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Detail < b.Detail
	})
}

func writeDatabase(path string, records []Record, manifest *Manifest) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	dataFile, dataPath, err := createTemp(filepath.Dir(path), ".ipintel-data-*")
	if err != nil {
		return err
	}
	defer os.Remove(dataPath)

	enc, err := newZstdWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		dataFile.Close()
		return err
	}
	defer enc.Close()

	var index []BlockHeader
	var dataLen int64
	blockSize := manifest.BlockSize
	for start := 0; start < len(records); start += blockSize {
		end := start + blockSize
		if end > len(records) {
			end = len(records)
		}
		block := records[start:end]
		raw := encodeRecords(block)
		compressed := enc.EncodeAll(raw, nil)
		first := block[0]
		maxEnd := block[0].End
		for _, r := range block[1:] {
			if bytes.Compare(r.End[:], maxEnd[:]) > 0 {
				maxEnd = r.End
			}
		}
		index = append(index, BlockHeader{
			Family:       first.Family,
			FirstStart:   addrString(first.Family, first.Start),
			MaxEnd:       addrString(first.Family, maxEnd),
			Count:        len(block),
			Offset:       dataLen,
			Compressed:   len(compressed),
			Uncompressed: len(raw),
		})
		if _, err := dataFile.Write(compressed); err != nil {
			dataFile.Close()
			return err
		}
		dataLen += int64(len(compressed))
	}
	if err := dataFile.Sync(); err != nil {
		dataFile.Close()
		return err
	}
	if _, err := dataFile.Seek(0, 0); err != nil {
		dataFile.Close()
		return err
	}
	manifest.BlockCount = len(index)
	manifest.RecordCount = len(records)
	manifest.FormatVersion = FormatVersion
	manifestBytes, err := marshalJSON(manifest)
	if err != nil {
		dataFile.Close()
		return err
	}
	indexBytes, err := marshalJSON(index)
	if err != nil {
		dataFile.Close()
		return err
	}
	dataOffset := int64(headerSize + len(manifestBytes) + len(indexBytes))
	final, finalPath, err := createTemp(filepath.Dir(path), ".ipintel-*")
	if err != nil {
		dataFile.Close()
		return err
	}
	defer os.Remove(finalPath)
	header := make([]byte, headerSize)
	copy(header[:8], FormatMagic)
	binary.LittleEndian.PutUint32(header[8:12], FormatVersion)
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(manifestBytes)))
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(indexBytes)))
	binary.LittleEndian.PutUint64(header[20:28], uint64(dataOffset))
	if _, err := final.Write(header); err != nil {
		final.Close()
		dataFile.Close()
		return err
	}
	if _, err := final.Write(manifestBytes); err != nil {
		final.Close()
		dataFile.Close()
		return err
	}
	if _, err := final.Write(indexBytes); err != nil {
		final.Close()
		dataFile.Close()
		return err
	}
	if _, err := io.Copy(final, dataFile); err != nil {
		final.Close()
		dataFile.Close()
		return err
	}
	if err := final.Sync(); err != nil {
		final.Close()
		dataFile.Close()
		return err
	}
	if err := final.Close(); err != nil {
		dataFile.Close()
		return err
	}
	dataFile.Close()
	if err := renameFile(finalPath, path); err != nil {
		return err
	}
	return nil
}

func encodeRecords(records []Record) []byte {
	var b bytes.Buffer
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(records)))
	b.Write(tmp[:])
	for _, r := range records {
		b.WriteByte(r.Family)
		b.Write(r.Start[:])
		b.Write(r.End[:])
		binary.LittleEndian.PutUint16(tmp[:2], r.SourceID)
		b.Write(tmp[:2])
		writeString(&b, r.Category)
		b.WriteByte(r.Confidence)
		binary.LittleEndian.PutUint32(tmp[:], r.ASN)
		b.Write(tmp[:])
		writeString(&b, r.Org)
		writeString(&b, r.Country)
		writeString(&b, r.Detail)
	}
	return b.Bytes()
}

func writeString(b *bytes.Buffer, s string) {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(s)))
	b.Write(tmp[:])
	b.WriteString(s)
}

func decodeRecords(b []byte) ([]Record, error) {
	r := bytes.NewReader(b)
	var count uint32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return nil, err
	}
	if count > 1_000_000 {
		return nil, fmt.Errorf("block record count too large: %d", count)
	}
	out := make([]Record, 0, count)
	for i := uint32(0); i < count; i++ {
		var rec Record
		fam, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		rec.Family = fam
		if _, err := io.ReadFull(r, rec.Start[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(r, rec.End[:]); err != nil {
			return nil, err
		}
		var src [2]byte
		if _, err := io.ReadFull(r, src[:]); err != nil {
			return nil, err
		}
		rec.SourceID = binary.LittleEndian.Uint16(src[:])
		rec.Category, err = readString(r)
		if err != nil {
			return nil, err
		}
		conf, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		rec.Confidence = conf
		var asn [4]byte
		if _, err := io.ReadFull(r, asn[:]); err != nil {
			return nil, err
		}
		rec.ASN = binary.LittleEndian.Uint32(asn[:])
		rec.Org, err = readString(r)
		if err != nil {
			return nil, err
		}
		rec.Country, err = readString(r)
		if err != nil {
			return nil, err
		}
		rec.Detail, err = readString(r)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

func readString(r *bytes.Reader) (string, error) {
	var n uint32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return "", err
	}
	if n > 4*1024*1024 {
		return "", fmt.Errorf("string too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
