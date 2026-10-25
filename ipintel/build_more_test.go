package ipintel

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

type fakeTempFile struct {
	buf        bytes.Buffer
	readErr    error
	writeErr   error
	writeErrAt int
	writeCalls int
	syncErr    error
	seekErr    error
	closeErr   error
}

func (f *fakeTempFile) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	return f.buf.Read(p)
}
func (f *fakeTempFile) Write(p []byte) (int, error) {
	f.writeCalls++
	if f.writeErr != nil || (f.writeErrAt > 0 && f.writeCalls >= f.writeErrAt) {
		return 0, errors.New("write")
	}
	return f.buf.Write(p)
}
func (f *fakeTempFile) Seek(int64, int) (int64, error) {
	if f.seekErr != nil {
		return 0, f.seekErr
	}
	return 0, nil
}
func (f *fakeTempFile) Sync() error {
	return f.syncErr
}
func (f *fakeTempFile) Close() error {
	return f.closeErr
}

func findSpec(t *testing.T, name string) sourceSpec {
	t.Helper()
	for _, spec := range sourceSpecs(Options{}) {
		if spec.Name == name {
			return spec
		}
	}
	t.Fatalf("source %q not found", name)
	return sourceSpec{}
}

func TestSourceFiles(t *testing.T) {
	dir := t.TempDir()
	spec := findSpec(t, "aws")
	if err := os.WriteFile(filepath.Join(dir, spec.Files[0].Name), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".meta"), 0755); err != nil {
		t.Fatal(err)
	}
	state, _ := json.Marshal(fileState{URL: spec.Files[0].URL, ETag: `"v1"`})
	if err := os.WriteFile(filepath.Join(dir, ".meta", spec.Files[0].Name+".json"), state, 0644); err != nil {
		t.Fatal(err)
	}
	got, ok, err := sourceFiles(dir, spec)
	if err != nil || !ok || len(got) != 1 || got[0].ETag != `"v1"` {
		t.Fatalf("sourceFiles = %+v, %v, %v", got, ok, err)
	}

	// Partial optional source is skipped.
	optional := findSpec(t, "cloudflare")
	if err := os.WriteFile(filepath.Join(dir, optional.Files[0].Name), []byte("1.2.3.0/24"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := sourceFiles(dir, optional); err != nil || ok {
		t.Fatalf("partial optional = %v, %v", ok, err)
	}
	// Partial required source is an error.
	required := findSpec(t, "x4b-vpn")
	if err := os.WriteFile(filepath.Join(dir, required.Files[0].Name), []byte("1.2.3.0/24"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sourceFiles(dir, required); err == nil {
		t.Fatal("partial required source should fail")
	}
}

func TestSourceFilesErrors(t *testing.T) {
	dir := t.TempDir()
	spec := sourceSpec{Name: "custom", Files: []fetchFile{{Name: "missing", URL: "u"}}}
	if _, ok, err := sourceFiles(dir, spec); err != nil || ok {
		t.Fatalf("missing = %v, %v", ok, err)
	}
	if err := os.Symlink("loop", filepath.Join(dir, "loop")); err != nil {
		t.Fatal(err)
	}
	spec = sourceSpec{Name: "custom", Files: []fetchFile{{Name: "loop", URL: "u"}}}
	if _, _, err := sourceFiles(dir, spec); err == nil {
		t.Fatal("stat error should fail")
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0755); err != nil {
		t.Fatal(err)
	}
	spec = sourceSpec{Name: "custom", Files: []fetchFile{{Name: "d", URL: "u"}}}
	if _, _, err := sourceFiles(dir, spec); err == nil {
		t.Fatal("hash error should fail")
	}
}

func TestReadOpenASNBuildID(t *testing.T) {
	dir := t.TempDir()
	if got := readOpenASNBuildID(dir); got != "" {
		t.Fatalf("missing build id = %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "openasn-build.json"), []byte("{"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := readOpenASNBuildID(dir); got != "" {
		t.Fatalf("bad build id = %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "openasn-build.json"), []byte(`{"build_id":"abc"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if got := readOpenASNBuildID(dir); got != "abc" {
		t.Fatalf("build id = %q", got)
	}
}

func TestBuild(t *testing.T) {
	raw := t.TempDir()
	aws := `{"prefixes":[{"ip_prefix":"1.2.3.0/24","region":"r","service":"s"},{"ip_prefix":"1.2.3.0/24","region":"r","service":"s"}],"ipv6_prefixes":[{"ipv6_prefix":"2606:4700::/32","region":"r","service":"s"}]}`
	if err := os.WriteFile(filepath.Join(raw, "aws-ip-ranges.json"), []byte(aws), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raw, "openasn-build.json"), []byte(`{"build_id":"build-1"}`), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "db.bin")
	m, err := Build(BuildOptions{RawDir: raw, OutFile: out, Exclude: excludeAllExcept("aws"), BlockSize: 0})
	if err != nil {
		t.Fatal(err)
	}
	if m.RecordCount != 2 || m.OpenASNBuild != "build-1" || m.BlockSize != DefaultBlock {
		t.Fatalf("manifest = %+v", m)
	}
	if len(m.Sources) != 1 || m.Sources[0].Homepage == "" || m.Sources[0].License == "" {
		t.Fatalf("sources = %+v", m.Sources)
	}

	base, err := Build(BuildOptions{RawDir: t.TempDir(), OutFile: filepath.Join(t.TempDir(), "base.bin"),
		BaseDB: out, Exclude: excludeAllExcept("aws")})
	if err != nil {
		t.Fatal(err)
	}
	if base.RecordCount != 2 {
		t.Fatalf("base reuse = %+v", base)
	}
}

func TestBuildSourceFilesError(t *testing.T) {
	raw := t.TempDir()
	if err := os.Symlink("aws-ip-ranges.json", filepath.Join(raw, "aws-ip-ranges.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(BuildOptions{RawDir: raw, OutFile: filepath.Join(t.TempDir(), "db"),
		Exclude: excludeAllExcept("aws")}); err == nil {
		t.Fatal("sourceFiles error should fail")
	}
}

func TestBuildASNsAndBadASNBase(t *testing.T) {
	raw := t.TempDir()
	if err := os.WriteFile(filepath.Join(raw, "bad-asn-list.csv"), []byte("ASN,Entity\n64500,Test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raw, "aws-ip-ranges.json"), []byte(`{"prefixes":[{"ip_prefix":"1.2.3.0/24"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "db")
	if _, err := Build(BuildOptions{RawDir: raw, OutFile: out, Exclude: excludeAllExcept("aws", "bad-asn-list")}); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "base")
	rec := testRecord(t, "1.2.3.0/24", 0, "hosting", 10, 0, "", "", "{}")
	if err := writeDatabase(base, []Record{rec, rec}, &Manifest{
		FormatVersion: FormatVersion, BlockSize: 8,
		Sources: []SourceMeta{{ID: 0, Name: "bad-asn-list"}},
		ASNs:    map[uint32]string{64500: "Test"},
	}); err != nil {
		t.Fatal(err)
	}
	m, err := Build(BuildOptions{RawDir: t.TempDir(), OutFile: filepath.Join(t.TempDir(), "out"),
		BaseDB: base, Exclude: excludeAllExcept("bad-asn-list")})
	if err != nil || m.RecordCount != 1 || m.ASNs[64500] != "Test" {
		t.Fatalf("bad-asn base = %+v, %v", m, err)
	}
}

func TestBuildErrors(t *testing.T) {
	if _, err := Build(BuildOptions{RawDir: t.TempDir(), OutFile: filepath.Join(t.TempDir(), "db"),
		Exclude: excludeAllExcept("x4b-vpn")}); err == nil {
		t.Fatal("missing required source should fail")
	}
	if _, err := Build(BuildOptions{RawDir: t.TempDir(), OutFile: filepath.Join(t.TempDir(), "db"),
		Exclude: excludeAllExcept("aws")}); err == nil {
		t.Fatal("empty build should fail")
	}
	raw := t.TempDir()
	if err := os.WriteFile(filepath.Join(raw, "aws-ip-ranges.json"), []byte("{"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(BuildOptions{RawDir: raw, OutFile: filepath.Join(t.TempDir(), "db"),
		Exclude: excludeAllExcept("aws")}); err == nil {
		t.Fatal("parse error should fail")
	}
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	goodRaw := t.TempDir()
	if err := os.WriteFile(filepath.Join(goodRaw, "aws-ip-ranges.json"), []byte(`{"prefixes":[{"ip_prefix":"1.2.3.0/24"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(BuildOptions{RawDir: goodRaw, OutFile: filepath.Join(blocker, "db"),
		Exclude: excludeAllExcept("aws")}); err == nil {
		t.Fatal("write error should fail")
	}
	if _, err := Build(BuildOptions{RawDir: raw, OutFile: filepath.Join(t.TempDir(), "db"),
		BaseDB: filepath.Join(t.TempDir(), "missing"), Exclude: excludeAllExcept("aws")}); err == nil {
		t.Fatal("missing base should fail")
	}
	badBase := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(badBase, []byte("bad"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(BuildOptions{RawDir: raw, OutFile: filepath.Join(t.TempDir(), "db"),
		BaseDB: badBase, Exclude: excludeAllExcept("aws")}); err == nil {
		t.Fatal("bad base should fail")
	}
}

func TestLoadBase(t *testing.T) {
	if _, _, _, _, err := loadBase(""); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := loadBase(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing base should fail")
	}
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("bad"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := loadBase(bad); err == nil {
		t.Fatal("bad base should fail")
	}
	broken := buildRawDB(t, `{"format_version":1}`, `[{"family":4,"first_start":"1.2.3.0","max_end":"1.2.3.255","compressed_size":10,"uncompressed_size":10}]`, nil)
	if _, _, _, _, err := loadBase(writeTemp(t, broken)); err == nil {
		t.Fatal("base with unreadable blocks should fail")
	}
	path := newTestDBPath(t)
	records, sources, asns, buildID, err := loadBase(path)
	if err != nil || len(records) == 0 || len(sources) == 0 || len(asns) == 0 || buildID != "" {
		t.Fatalf("loadBase = %v %v %v %q %v", records, sources, asns, buildID, err)
	}
}

func TestWriteDatabaseErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	if err := os.WriteFile(path+".blocker", []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeDatabase(filepath.Join(path+".blocker", "db"), nil, &Manifest{}); err == nil {
		t.Fatal("mkdir error should fail")
	}
	recs := []Record{testRecord(t, "1.2.3.0/24", 0, "hosting", 1, 0, "", "", "{}")}
	man := &Manifest{FormatVersion: FormatVersion, BlockSize: 8}

	t.Run("create temp default", func(t *testing.T) {
		old := createTemp
		createTemp = old
		if _, _, err := createTemp(filepath.Join(t.TempDir(), "missing", "dir"), "x"); err == nil {
			t.Fatal("default createTemp error should fail")
		}
	})
	t.Run("create data", func(t *testing.T) {
		old := createTemp
		createTemp = func(string, string) (tempFile, string, error) { return nil, "", errors.New("create") }
		t.Cleanup(func() { createTemp = old })
		if err := writeDatabase(path, recs, man); err == nil {
			t.Fatal("create data error")
		}
	})
	t.Run("zstd writer", func(t *testing.T) {
		old := newZstdWriter
		newZstdWriter = func(io.Writer, ...zstd.EOption) (*zstd.Encoder, error) { return nil, errors.New("zstd") }
		t.Cleanup(func() { newZstdWriter = old })
		if err := writeDatabase(path, recs, man); err == nil {
			t.Fatal("zstd error")
		}
	})
	t.Run("marshal manifest", func(t *testing.T) {
		old := marshalJSON
		marshalJSON = func(any) ([]byte, error) { return nil, errors.New("marshal") }
		t.Cleanup(func() { marshalJSON = old })
		if err := writeDatabase(path, recs, man); err == nil {
			t.Fatal("manifest marshal error")
		}
	})
	t.Run("marshal index", func(t *testing.T) {
		old := marshalJSON
		calls := 0
		marshalJSON = func(v any) ([]byte, error) {
			calls++
			if calls == 2 {
				return nil, errors.New("marshal")
			}
			return old(v)
		}
		t.Cleanup(func() { marshalJSON = old })
		if err := writeDatabase(path, recs, man); err == nil {
			t.Fatal("index marshal error")
		}
	})
	t.Run("create final", func(t *testing.T) {
		old := createTemp
		calls := 0
		createTemp = func(dir, pattern string) (tempFile, string, error) {
			calls++
			if calls == 2 {
				return nil, "", errors.New("create final")
			}
			return old(dir, pattern)
		}
		t.Cleanup(func() { createTemp = old })
		if err := writeDatabase(path, recs, man); err == nil {
			t.Fatal("create final error")
		}
	})
	for _, tc := range []struct {
		name string
		data *fakeTempFile
		fin  *fakeTempFile
	}{
		{"data write", &fakeTempFile{writeErr: errors.New("w")}, &fakeTempFile{}},
		{"data sync", &fakeTempFile{syncErr: errors.New("s")}, &fakeTempFile{}},
		{"data seek", &fakeTempFile{seekErr: errors.New("s")}, &fakeTempFile{}},
		{"final write", &fakeTempFile{}, &fakeTempFile{writeErr: errors.New("w")}},
		{"final write manifest", &fakeTempFile{}, &fakeTempFile{writeErrAt: 2}},
		{"final write index", &fakeTempFile{}, &fakeTempFile{writeErrAt: 3}},
		{"final sync", &fakeTempFile{}, &fakeTempFile{syncErr: errors.New("s")}},
		{"final close", &fakeTempFile{}, &fakeTempFile{closeErr: errors.New("c")}},
		{"data read", &fakeTempFile{readErr: errors.New("r")}, &fakeTempFile{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := createTemp
			calls := 0
			createTemp = func(string, string) (tempFile, string, error) {
				calls++
				if calls == 1 {
					return tc.data, filepath.Join(t.TempDir(), "data"), nil
				}
				return tc.fin, filepath.Join(t.TempDir(), "final"), nil
			}
			t.Cleanup(func() { createTemp = old })
			if err := writeDatabase(path, recs, man); err == nil {
				t.Fatalf("%s should fail", tc.name)
			}
		})
	}
	t.Run("rename", func(t *testing.T) {
		old := renameFile
		renameFile = func(string, string) error { return errors.New("rename") }
		t.Cleanup(func() { renameFile = old })
		if err := writeDatabase(path, recs, man); err == nil {
			t.Fatal("rename error")
		}
	})
}
