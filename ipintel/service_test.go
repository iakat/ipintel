package ipintel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
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
	path := filepath.Join(dir, "test.bin")
	if err := writeDatabase(path, records, manifest); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestServiceEndpoints(t *testing.T) {
	db := testDB(t)
	svc := NewService(db)
	h := svc.Handler()

	cases := []struct {
		path   string
		status int
		body   string
	}{
		{"/healthz", http.StatusOK, "ok\n"},
		{"/v1/lookup?ip=1.2.3.4", http.StatusOK, `"ip":"1.2.3.4"`},
		{"/v1/lookup/1.2.3.4", http.StatusOK, `"ip":"1.2.3.4"`},
		{"/v1/lookup", http.StatusBadRequest, "missing ip"},
		{"/v1/lookup?ip=not-an-ip", http.StatusBadRequest, "invalid IP"},
		{"/v1/sources", http.StatusOK, `"name":"test"`},
		{"/v1/manifest", http.StatusOK, `"format_version":1`},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.body) {
			t.Errorf("%s = %d %q, want %d containing %q", tc.path, w.Code, w.Body.String(), tc.status, tc.body)
		}
	}
}

func TestServiceNilDatabase(t *testing.T) {
	svc := NewService(nil)
	h := svc.Handler()
	for _, path := range []string{"/v1/lookup?ip=1.2.3.4", "/v1/sources", "/v1/manifest"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "database not loaded") {
			t.Errorf("%s = %d %q", path, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Errorf("healthz = %d", w.Code)
	}
}

func TestServiceSwap(t *testing.T) {
	first := testDB(t)
	second := testDB(t)
	svc := NewService(first)
	if got := svc.Swap(second); got != first {
		t.Fatal("swap did not return the previous database")
	}
	if got := svc.Swap(nil); got != second {
		t.Fatal("second swap did not return the second database")
	}
}

func TestWriteErrorTrims(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusTeapot, "  bad  ")
	if w.Code != http.StatusTeapot {
		t.Fatalf("status = %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "bad" {
		t.Fatalf("error = %q", body["error"])
	}
}
