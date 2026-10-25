package ipintel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func newTestDBPath(t *testing.T) string {
	t.Helper()
	records := []Record{
		testRecord(t, "1.2.3.0/24", 0, "hosting", 80, 64500, "Test Org", "DE", `{"provider":"test"}`),
	}
	manifest := &Manifest{
		FormatVersion: FormatVersion,
		BuiltAt:       time.Unix(100, 0).UTC(),
		BlockSize:     8,
		Sources: []SourceMeta{
			{ID: 0, Name: "test", Homepage: "https://example.com", License: "MIT"},
		},
		ASNs: map[uint32]string{64500: "Test Org"},
	}
	path := filepath.Join(t.TempDir(), "test.bin")
	if err := writeDatabase(path, records, manifest); err != nil {
		t.Fatal(err)
	}
	return path
}

func validDBBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(newTestDBPath(t))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func buildRawDB(t *testing.T, manifestJSON, indexJSON string, data []byte) []byte {
	t.Helper()
	manifest := []byte(manifestJSON)
	index := []byte(indexJSON)
	out := make([]byte, headerSize, headerSize+len(manifest)+len(index)+len(data))
	copy(out[:8], FormatMagic)
	binary.LittleEndian.PutUint32(out[8:12], FormatVersion)
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(manifest)))
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(index)))
	binary.LittleEndian.PutUint64(out[20:28], uint64(headerSize+len(manifest)+len(index)))
	out = append(out, manifest...)
	out = append(out, index...)
	out = append(out, data...)
	return out
}

func writeTemp(t *testing.T, b []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db.bin")
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenErrors(t *testing.T) {
	base := validDBBytes(t)
	headerOnly := func(manifestLen, indexLen uint32, offset uint64) []byte {
		b := make([]byte, headerSize)
		copy(b[:8], FormatMagic)
		binary.LittleEndian.PutUint32(b[8:12], FormatVersion)
		binary.LittleEndian.PutUint32(b[12:16], manifestLen)
		binary.LittleEndian.PutUint32(b[16:20], indexLen)
		binary.LittleEndian.PutUint64(b[20:28], offset)
		return b
	}
	cases := []struct {
		name string
		data []byte
	}{
		{"short header", []byte{1, 2, 3}},
		{"bad magic", mutate(base, func(b []byte) { copy(b[:8], "BADMAGIC") })},
		{"bad version", mutate(base, func(b []byte) { binary.LittleEndian.PutUint32(b[8:12], 99) })},
		{"huge manifest", mutate(base, func(b []byte) { binary.LittleEndian.PutUint32(b[12:16], 64*1024*1024+1) })},
		{"huge index", mutate(base, func(b []byte) { binary.LittleEndian.PutUint32(b[16:20], 64*1024*1024+1) })},
		{"bad offset", mutate(base, func(b []byte) { binary.LittleEndian.PutUint64(b[20:28], 0) })},
		{"short manifest", headerOnly(10, 0, headerSize+10)},
		{"short index", headerOnly(0, 10, headerSize+10)},
		{"bad manifest json", buildRawDB(t, "{", "[]", nil)},
		{"wrong manifest version", buildRawDB(t, `{"format_version":2}`, "[]", nil)},
		{"bad index json", buildRawDB(t, `{"format_version":1}`, "{", nil)},
		{"bad first start", buildRawDB(t, `{"format_version":1}`, `[{"family":4,"first_start":"bad","max_end":"1.2.3.4"}]`, nil)},
		{"bad max end", buildRawDB(t, `{"format_version":1}`, `[{"family":4,"first_start":"1.2.3.4","max_end":"bad"}]`, nil)},
		{"family mismatch", buildRawDB(t, `{"format_version":1}`, `[{"family":6,"first_start":"1.2.3.4","max_end":"1.2.3.255"}]`, nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.data)
			if _, err := Open(path); err == nil {
				t.Fatal("Open should fail")
			}
			if _, err := OpenInMemory(path); err == nil {
				t.Fatal("OpenInMemory should fail")
			}
		})
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing db should fail")
	}
	if _, err := OpenInMemory(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing in-memory db should fail")
	}
}

func mutate(base []byte, fn func([]byte)) []byte {
	out := append([]byte(nil), base...)
	fn(out)
	return out
}

func TestOpenDecoderError(t *testing.T) {
	old := newZstdReader
	newZstdReader = func(io.Reader, ...zstd.DOption) (*zstd.Decoder, error) {
		return nil, errors.New("no decoder")
	}
	t.Cleanup(func() { newZstdReader = old })
	if _, err := Open(writeTemp(t, validDBBytes(t))); err == nil {
		t.Fatal("decoder error should fail")
	}
}

func TestDBCloseManifest(t *testing.T) {
	var nilDB *DB
	if err := nilDB.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(newTestDBPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if db.Manifest().RecordCount == 0 {
		t.Fatal("empty manifest")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	mem, err := OpenInMemory(newTestDBPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDBAllRecordsAndReadBlockErrors(t *testing.T) {
	db := &DB{blocks: []runtimeBlock{{header: BlockHeader{Compressed: 0}}}}
	if _, err := db.AllRecords(); err == nil {
		t.Fatal("invalid block should fail")
	}
	mem := &DB{data: []byte{1, 2, 3}, dataOffset: 99, decoder: mustDecoder(t)}
	if _, err := mem.readBlock(runtimeBlock{header: BlockHeader{Compressed: 1, Uncompressed: 1}}); err == nil {
		t.Fatal("out-of-bounds in-memory block should fail")
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	fileDB := &DB{f: closed, decoder: mustDecoder(t)}
	if _, err := fileDB.readBlock(runtimeBlock{header: BlockHeader{Compressed: 1, Uncompressed: 1}}); err == nil {
		t.Fatal("closed file read should fail")
	}
	bad := &DB{data: []byte("not zstd"), dataOffset: 0, decoder: mustDecoder(t)}
	if _, err := bad.readBlock(runtimeBlock{header: BlockHeader{Compressed: 8, Uncompressed: 1}}); err == nil {
		t.Fatal("bad zstd block should fail")
	}
	raw := encodeRecords([]Record{testRecord(t, "1.2.3.0/24", 0, "hosting", 1, 0, "", "", "{}")})
	enc, _ := zstd.NewWriter(nil)
	compressed := enc.EncodeAll(raw, nil)
	enc.Close()
	sizeDB := &DB{data: compressed, decoder: mustDecoder(t)}
	if _, err := sizeDB.readBlock(runtimeBlock{header: BlockHeader{Compressed: len(compressed), Uncompressed: len(raw) + 1}}); err == nil {
		t.Fatal("size mismatch should fail")
	}
}

func mustDecoder(t *testing.T) *zstd.Decoder {
	t.Helper()
	d, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDBLookupErrorsAndMetadata(t *testing.T) {
	db, err := Open(newTestDBPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Lookup("bad"); err == nil {
		t.Fatal("bad lookup IP should fail")
	}
	if got := db.sourceName(99); got != "source-99" {
		t.Fatalf("sourceName = %q", got)
	}
	res, err := db.Lookup("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if res.ASN != 64500 || res.Org != "Test Org" || res.Country != "DE" {
		t.Fatalf("metadata = %+v", res)
	}
	badBlock := &DB{
		manifest: Manifest{Sources: []SourceMeta{{Name: "test"}}},
		blocks: []runtimeBlock{{
			family: 4,
			header: BlockHeader{Compressed: 0},
		}},
	}
	badBlock.blocks[0].first = mustAddrBytes4(t, "1.2.3.0")
	badBlock.blocks[0].max = mustAddrBytes4(t, "1.2.3.255")
	if _, err := badBlock.Lookup("1.2.3.4"); err == nil {
		t.Fatal("lookup readBlock error should fail")
	}
}

func mustAddrBytes4(t *testing.T, s string) (out [16]byte) {
	t.Helper()
	p, err := parsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	family, start, _ := prefixRange(p)
	if family != 4 {
		t.Fatal("not IPv4")
	}
	return start
}

func TestDBRawDetails(t *testing.T) {
	if got := rawDetail(""); got != nil {
		t.Fatalf("empty rawDetail = %v", got)
	}
	if got := string(rawDetail(`{"a":1}`)); got != `{"a":1}` {
		t.Fatalf("valid rawDetail = %s", got)
	}
	if got := string(rawDetail("not-json")); got != `"not-json"` {
		t.Fatalf("invalid rawDetail = %s", got)
	}
	if got := string(rawJSON(make(chan int))); got != `{}` {
		t.Fatalf("rawJSON error = %s", got)
	}
	if got := detailJSON(make(chan int)); got != `{}` {
		t.Fatalf("detailJSON error = %s", got)
	}
}

func TestReadStringAndDecodeErrors(t *testing.T) {
	var buf bytes.Buffer
	writeString(&buf, "hello")
	if got, err := readString(bytes.NewReader(buf.Bytes())); err != nil || got != "hello" {
		t.Fatalf("readString = %q, %v", got, err)
	}
	var tooBig [4]byte
	binary.LittleEndian.PutUint32(tooBig[:], 4*1024*1024+1)
	if _, err := readString(bytes.NewReader(tooBig[:])); err == nil {
		t.Fatal("too-large string should fail")
	}
	if _, err := readString(bytes.NewReader([]byte{1, 2})); err == nil {
		t.Fatal("short string length should fail")
	}
	if _, err := readString(bytes.NewReader([]byte{1, 0, 0, 0})); err == nil {
		t.Fatal("short string body should fail")
	}
	rec := testRecord(t, "1.2.3.0/24", 0, "hosting", 1, 0, "", "", "{}")
	encoded := encodeRecords([]Record{rec})
	if _, err := decodeRecords(nil); err == nil {
		t.Fatal("empty decode should fail")
	}
	tooMany := make([]byte, 4)
	binary.LittleEndian.PutUint32(tooMany, 1_000_001)
	if _, err := decodeRecords(tooMany); err == nil {
		t.Fatal("too many records should fail")
	}
	for n := 0; n < len(encoded); n++ {
		if _, err := decodeRecords(encoded[:n]); err == nil {
			t.Fatalf("truncated decode at %d should fail", n)
		}
	}
	got, err := decodeRecords(encoded)
	if err != nil || len(got) != 1 {
		t.Fatalf("decode = %+v, %v", got, err)
	}
}

func TestSortRecords(t *testing.T) {
	records := []Record{
		testRecord(t, "1.0.0.0/30", 0, "vpn", 1, 0, "", "", "b"),
		testRecord(t, "1.0.0.0/24", 0, "vpn", 1, 0, "", "", "a"),
		testRecord(t, "2.0.0.0/24", 1, "vpn", 1, 0, "", "", "b"),
		testRecord(t, "1.0.0.0/24", 1, "vpn", 1, 0, "", "", "b"),
		testRecord(t, "1.0.0.0/24", 0, "vpn", 1, 0, "", "", "b"),
		testRecord(t, "1.0.0.0/24", 0, "hosting", 1, 0, "", "", "b"),
		testRecord(t, "1.0.0.0/24", 0, "hosting", 1, 0, "", "", "a"),
		{Family: 6},
	}
	sortRecords(records)
	if records[0].Family != 4 || records[len(records)-1].Family != 6 {
		t.Fatalf("family sort = %+v", records)
	}
	if got := recordKey(records[0]); !strings.Contains(got, "vpn") {
		t.Fatalf("recordKey = %q", got)
	}
}

func TestLookupMixedFamiliesAndEvidenceSort(t *testing.T) {
	dir := t.TempDir()
	records := []Record{
		testRecord(t, "1.2.3.0/24", 0, "hosting", 10, 0, "", "", "{}"),
		testRecord(t, "1.2.3.0/24", 0, "vpn", 20, 0, "", "", "{}"),
		testRecord(t, "1.2.3.0/24", 0, "hosting", 30, 0, "", "", "{}"),
		testRecord(t, "2606:4700::/32", 0, "hosting", 40, 0, "", "", "{}"),
	}
	path := filepath.Join(dir, "mixed.bin")
	if err := writeDatabase(path, records, &Manifest{
		FormatVersion: FormatVersion, BlockSize: 10,
		Sources: []SourceMeta{{ID: 0, Name: "test"}},
	}); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Lookup("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Evidence) != 3 {
		t.Fatalf("evidence = %+v", res.Evidence)
	}
	for i := 1; i < len(res.Evidence); i++ {
		if res.Evidence[i-1].Category > res.Evidence[i].Category {
			t.Fatalf("evidence not sorted by category: %+v", res.Evidence)
		}
	}
}
