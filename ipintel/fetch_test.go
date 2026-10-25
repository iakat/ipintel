package ipintel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnsureFileUsesHEADAndSkipsUnchanged(t *testing.T) {
	var gets int32
	var etag atomic.Value
	etag.Store(`"v1"`)
	var body atomic.Value
	body.Store("hello world")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag.Load().(string))
		b := body.Load().(string)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
		if r.Method == http.MethodHead {
			return
		}
		if r.Header.Get("If-None-Match") == etag.Load().(string) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		atomic.AddInt32(&gets, 1)
		_, _ = w.Write([]byte(b))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "file.txt")
	meta := filepath.Join(dir, ".meta", "file.json")
	client := &http.Client{Timeout: 5 * time.Second}

	changed, err := ensureFile(context.Background(), client, srv.URL, dest, meta, nil, false)
	if err != nil || !changed {
		t.Fatalf("first ensureFile = %v, %v", changed, err)
	}
	changed, err = ensureFile(context.Background(), client, srv.URL, dest, meta, nil, false)
	if err != nil || changed {
		t.Fatalf("second ensureFile = %v, %v", changed, err)
	}
	if got := atomic.LoadInt32(&gets); got != 1 {
		t.Fatalf("GET count = %d, want 1", got)
	}

	etag.Store(`"v2"`)
	body.Store("hello again")
	changed, err = ensureFile(context.Background(), client, srv.URL, dest, meta, nil, false)
	if err != nil || !changed {
		t.Fatalf("changed ensureFile = %v, %v", changed, err)
	}
	if got := atomic.LoadInt32(&gets); got != 2 {
		t.Fatalf("GET count after change = %d, want 2", got)
	}
	b, _ := os.ReadFile(dest)
	if string(b) != "hello again" {
		t.Fatalf("body = %q", b)
	}
}

func TestEnsureFileMissingRawWithoutUpdateDownloads(t *testing.T) {
	var gets int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodHead {
			return
		}
		atomic.AddInt32(&gets, 1)
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	dest := filepath.Join(dir, "file.txt")
	meta := filepath.Join(dir, ".meta", "file.json")
	client := &http.Client{Timeout: 5 * time.Second}
	if changed, err := ensureFile(context.Background(), client, srv.URL, dest, meta, nil, false); err != nil || !changed {
		t.Fatalf("first = %v, %v", changed, err)
	}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	if changed, err := ensureFile(context.Background(), client, srv.URL, dest, meta, nil, false); err != nil || !changed {
		t.Fatalf("missing raw without update = %v, %v", changed, err)
	}
	if got := atomic.LoadInt32(&gets); got != 2 {
		t.Fatalf("GET count = %d, want 2", got)
	}
}

func TestEnsureFileBaseSkipsMissingRaw(t *testing.T) {
	var gets int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodHead {
			return
		}
		atomic.AddInt32(&gets, 1)
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "file.txt")
	meta := filepath.Join(dir, ".meta", "file.json")
	client := &http.Client{Timeout: 5 * time.Second}
	if changed, err := ensureFile(context.Background(), client, srv.URL, dest, meta, nil, false); err != nil || !changed {
		t.Fatalf("first = %v, %v", changed, err)
	}
	state, err := readFileState(meta)
	if err != nil {
		t.Fatal(err)
	}
	base := &FileMeta{Name: "file.txt", URL: srv.URL, ETag: state.ETag, Bytes: state.Bytes}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	changed, err := ensureFile(context.Background(), client, srv.URL, dest, meta, base, true)
	if err != nil || changed {
		t.Fatalf("missing-raw update = %v, %v", changed, err)
	}
	if got := atomic.LoadInt32(&gets); got != 1 {
		t.Fatalf("GET count = %d, want 1", got)
	}
}

func TestEnsureFileFallsBackWhenHEADUnsupported(t *testing.T) {
	var gets int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("ETag", `"x"`)
		if r.Header.Get("If-None-Match") == `"x"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		atomic.AddInt32(&gets, 1)
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "file.txt")
	meta := filepath.Join(dir, ".meta", "file.json")
	client := &http.Client{Timeout: 5 * time.Second}
	if changed, err := ensureFile(context.Background(), client, srv.URL, dest, meta, nil, false); err != nil || !changed {
		t.Fatalf("first = %v, %v", changed, err)
	}
	if changed, err := ensureFile(context.Background(), client, srv.URL, dest, meta, nil, false); err != nil || changed {
		t.Fatalf("second = %v, %v", changed, err)
	}
	if got := atomic.LoadInt32(&gets); got != 1 {
		t.Fatalf("GET count = %d, want 1", got)
	}
}
