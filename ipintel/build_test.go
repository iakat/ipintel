package ipintel

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBuildReusesBaseSource(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.bin")
	rec := testRecord(t, "192.0.2.0/24", 0, "hosting", 95, 0, "", "", `{"provider":"aws"}`)
	manifest := &Manifest{
		FormatVersion: FormatVersion,
		BuiltAt:       time.Unix(1, 0).UTC(),
		BlockSize:     8,
		Sources:       []SourceMeta{{ID: 0, Name: "aws", Records: 1}},
	}
	sortRecords([]Record{rec})
	if err := writeDatabase(basePath, []Record{rec}, manifest); err != nil {
		t.Fatal(err)
	}

	exclude := map[string]bool{}
	for _, name := range SourceNames() {
		if name != "aws" {
			exclude[name] = true
		}
	}
	out := filepath.Join(dir, "out.bin")
	m, err := Build(BuildOptions{
		RawDir: dir, OutFile: out, BaseDB: basePath, Exclude: exclude,
		BlockSize: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.RecordCount != 1 || len(m.Sources) != 1 || m.Sources[0].Name != "aws" {
		t.Fatalf("manifest = %+v", m)
	}
	if m.Sources[0].Homepage != sourceHomepages["aws"] || m.Sources[0].License != "AWS public IP ranges" {
		t.Fatalf("source credit = %+v", m.Sources[0])
	}
	db, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Lookup("192.0.2.1")
	if err != nil || res.Score != 43 || res.Verdict != "hosting" {
		t.Fatalf("lookup = %+v, %v", res, err)
	}
}
