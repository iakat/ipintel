package ipintel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	retryBase = 0
	os.Exit(m.Run())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testResponse(status int, body string, header map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range header {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func testHTTPClient(rt roundTripFunc) *http.Client {
	return &http.Client{Transport: rt, Timeout: 5 * time.Second}
}

func excludeAllExcept(names ...string) map[string]bool {
	keep := map[string]bool{}
	for _, name := range names {
		keep[name] = true
	}
	out := map[string]bool{}
	for _, name := range SourceNames() {
		if !keep[name] {
			out[name] = true
		}
	}
	return out
}

func TestFetchWithOptions(t *testing.T) {
	oldClient := fetchClient
	t.Cleanup(func() { fetchClient = oldClient })

	var heads, gets int
	fetchClient = func() *http.Client {
		return testHTTPClient(func(r *http.Request) (*http.Response, error) {
			switch r.Method {
			case http.MethodHead:
				heads++
				return testResponse(http.StatusOK, "", map[string]string{"ETag": `"v1"`, "Content-Length": "7"}), nil
			default:
				gets++
				return testResponse(http.StatusOK, "payload", map[string]string{"ETag": `"v1"`}), nil
			}
		})
	}
	dir := t.TempDir()
	opts := FetchOptions{Exclude: excludeAllExcept("open-proxies")}
	if err := FetchWithOptions(context.Background(), dir, opts); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "open-proxies.txt")); err != nil || string(b) != "payload" {
		t.Fatalf("downloaded file = %q, %v", b, err)
	}
	if err := FetchWithOptions(context.Background(), dir, opts); err != nil {
		t.Fatal(err)
	}
	if heads != 2 || gets != 1 {
		t.Fatalf("heads/gets = %d/%d, want 2/1", heads, gets)
	}

	// No tasks at all, and both parallel clamps.
	if err := FetchWithOptions(context.Background(), t.TempDir(), FetchOptions{Exclude: excludeAllExcept()}); err != nil {
		t.Fatal(err)
	}
	if err := FetchWithOptions(context.Background(), t.TempDir(), FetchOptions{Exclude: excludeAllExcept(), Parallel: 0}); err != nil {
		t.Fatal(err)
	}
	if err := FetchWithOptions(context.Background(), t.TempDir(), FetchOptions{Exclude: excludeAllExcept(), Parallel: 100}); err != nil {
		t.Fatal(err)
	}
	if err := Fetch(context.Background(), t.TempDir(), Options{Exclude: excludeAllExcept()}); err != nil {
		t.Fatal(err)
	}
}

func TestFetchWithOptionsErrors(t *testing.T) {
	oldClient := fetchClient
	t.Cleanup(func() { fetchClient = oldClient })
	fetchClient = func() *http.Client {
		return testHTTPClient(func(r *http.Request) (*http.Response, error) {
			return testResponse(http.StatusNotFound, "", nil), nil
		})
	}

	// Optional source failure is skipped.
	if err := FetchWithOptions(context.Background(), t.TempDir(), FetchOptions{Exclude: excludeAllExcept("open-proxies")}); err != nil {
		t.Fatalf("optional source error = %v", err)
	}
	// Core source failure is fatal.
	if err := FetchWithOptions(context.Background(), t.TempDir(), FetchOptions{Exclude: excludeAllExcept("x4b-vpn")}); err == nil {
		t.Fatal("core source error should fail")
	}
}

func TestFetchWithOptionsBase(t *testing.T) {
	oldClient := fetchClient
	t.Cleanup(func() { fetchClient = oldClient })
	fetchClient = func() *http.Client {
		return testHTTPClient(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodHead {
				return testResponse(http.StatusOK, "", map[string]string{"ETag": `"v1"`, "Content-Length": "7"}), nil
			}
			return testResponse(http.StatusOK, "payload", map[string]string{"ETag": `"v1"`}), nil
		})
	}
	base := &Manifest{Sources: []SourceMeta{{
		Name: "open-proxies",
		Files: []FileMeta{{
			Name: "open-proxies.txt", URL: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
			ETag: `"v1"`, Bytes: 7,
		}},
	}}}
	err := FetchWithOptions(context.Background(), t.TempDir(), FetchOptions{
		Exclude: excludeAllExcept("open-proxies"), Base: base, AllowMissing: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestManifestFiles(t *testing.T) {
	if got := manifestFiles(nil); len(got) != 0 {
		t.Fatalf("nil manifest files = %+v", got)
	}
	m := &Manifest{Sources: []SourceMeta{{Files: []FileMeta{{Name: "a"}, {Name: "b"}}}}}
	if got := manifestFiles(m); len(got) != 2 || got["a"].Name != "a" {
		t.Fatalf("manifest files = %+v", got)
	}
}

func TestStateMatches(t *testing.T) {
	tests := []struct {
		name  string
		state fileState
		head  headInfo
		local int64
		want  bool
	}{
		{"empty url", fileState{}, headInfo{ETag: "x"}, 0, false},
		{"etag", fileState{URL: "u", ETag: "x"}, headInfo{ETag: "x"}, 0, true},
		{"last modified", fileState{URL: "u", LastModified: "m"}, headInfo{LastModified: "m"}, 0, true},
		{"size zero local", fileState{URL: "u", ContentLength: 10}, headInfo{ContentLength: 10}, 0, true},
		{"size equal", fileState{URL: "u", ContentLength: 10}, headInfo{ContentLength: 10}, 10, true},
		{"size mismatch", fileState{URL: "u", ContentLength: 10}, headInfo{ContentLength: 11}, 10, false},
		{"no validators", fileState{URL: "u"}, headInfo{ContentLength: 0}, 10, false},
	}
	for _, tc := range tests {
		if got := stateMatches(tc.state, tc.head, tc.local); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHeadRequest(t *testing.T) {
	success := testHTTPClient(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, "", map[string]string{"ETag": `"v1"`}), nil
	})
	if info, err := headRequest(context.Background(), success, "https://example.com"); err != nil || info.ETag != `"v1"` {
		t.Fatalf("head success = %+v, %v", info, err)
	}
	notFound := testHTTPClient(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusNotFound, "", nil), nil
	})
	if _, err := headRequest(context.Background(), notFound, "https://example.com"); err == nil {
		t.Fatal("404 head should fail")
	}
	var calls int
	retry := testHTTPClient(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return testResponse(http.StatusInternalServerError, "", nil), nil
		}
		return testResponse(http.StatusOK, "", nil), nil
	})
	if _, err := headRequest(context.Background(), retry, "https://example.com"); err != nil || calls != 2 {
		t.Fatalf("head retry = %d, %v", calls, err)
	}
	if _, err := headRequest(context.Background(), success, "://bad"); err == nil {
		t.Fatal("bad URL should fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	alwaysFail := testHTTPClient(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network")
	})
	oldRetry := retryBase
	retryBase = time.Hour
	t.Cleanup(func() { retryBase = oldRetry })
	if _, err := headRequest(ctx, alwaysFail, "https://example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled head = %v", err)
	}
}

func TestDownloadConditional(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "file.txt")
	client := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			return testResponse(http.StatusNotModified, "", nil), nil
		}
		return testResponse(http.StatusOK, "payload", map[string]string{"ETag": `"v1"`}), nil
	})
	res, err := downloadConditional(context.Background(), client, "https://example.com", dest, fileState{})
	if err != nil || !res.Changed || res.State.Bytes != 7 {
		t.Fatalf("download = %+v, %v", res, err)
	}
	res, err = downloadConditional(context.Background(), client, "https://example.com", dest, fileState{URL: "https://example.com", ETag: `"v1"`})
	if err != nil || res.Changed {
		t.Fatalf("not modified = %+v, %v", res, err)
	}

	notFound := testHTTPClient(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusNotFound, "", nil), nil
	})
	if _, err := downloadConditional(context.Background(), notFound, "https://example.com", dest, fileState{}); err == nil {
		t.Fatal("404 download should fail")
	}
	if _, err := downloadConditional(context.Background(), client, "://bad", dest, fileState{}); err == nil {
		t.Fatal("bad URL should fail")
	}
	if _, err := downloadConditional(context.Background(), client, "https://example.com", filepath.Join(dir, "missing", "file"), fileState{}); err == nil {
		t.Fatal("bad dest should fail")
	}
	empty := testHTTPClient(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, "", nil), nil
	})
	if _, err := downloadConditional(context.Background(), empty, "https://example.com", dest, fileState{}); err == nil {
		t.Fatal("empty response should fail")
	}
	if _, err := downloadConditional(context.Background(), client, "https://example.com", dir, fileState{}); err == nil {
		t.Fatal("rename to directory should fail")
	}

	// Copy failure cancels the context so the retry loop exits immediately.
	ctx, cancel := context.WithCancel(context.Background())
	failingBody := io.NopCloser(readerFunc(func([]byte) (int, error) {
		cancel()
		return 0, errors.New("read failed")
	}))
	copyFail := testHTTPClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{}, Body: failingBody, ContentLength: 10}, nil
	})
	if _, err := downloadConditional(ctx, copyFail, "https://example.com", dest, fileState{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("copy failure = %v", err)
	}

	// If-Modified-Since from LastModified and FetchedAt.
	var sawLast, sawFetched bool
	conditional := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("If-Modified-Since") == "Mon, 02 Jan 2006 15:04:05 GMT" {
			sawLast = true
		}
		if r.Header.Get("If-Modified-Since") == "Mon, 02 Jan 2006 15:04:05 GMT" {
			sawFetched = true
		}
		return testResponse(http.StatusNotModified, "", nil), nil
	})
	when := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
	if _, err := downloadConditional(context.Background(), conditional, "https://example.com", dest, fileState{LastModified: "Mon, 02 Jan 2006 15:04:05 GMT"}); err != nil {
		t.Fatal(err)
	}
	if _, err := downloadConditional(context.Background(), conditional, "https://example.com", dest, fileState{FetchedAt: when}); err != nil {
		t.Fatal(err)
	}
	if !sawLast || !sawFetched {
		t.Fatalf("conditional headers = %v/%v", sawLast, sawFetched)
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestWriteFileState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta.json")
	if err := writeFileState(path, fileState{URL: "u"}); err != nil {
		t.Fatal(err)
	}
	if state, err := readFileState(path); err != nil || state.URL != "u" {
		t.Fatalf("state = %+v, %v", state, err)
	}
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileState(filepath.Join(blocker, "meta.json"), fileState{}); err == nil {
		t.Fatal("mkdir error should fail")
	}
	writeFail := filepath.Join(dir, "writefail.json")
	if err := os.Mkdir(filepath.Join(writeFail+".part"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := writeFileState(writeFail, fileState{}); err == nil {
		t.Fatal("write error should fail")
	}
	renameFail := filepath.Join(dir, "renamefail.json")
	if err := os.MkdirAll(renameFail, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(renameFail, "child"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileState(renameFail, fileState{}); err == nil {
		t.Fatal("rename error should fail")
	}
}

func TestSHAAndChecksums(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if got, err := sha256File(file); err != nil || got == "" {
		t.Fatalf("sha256File = %q, %v", got, err)
	}
	if _, err := sha256File(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing sha256File should fail")
	}
	if _, err := sha256File(dir); err == nil {
		t.Fatal("directory sha256File should fail")
	}
	if err := verifyOpenASNChecksum(dir); err != nil {
		t.Fatalf("no openasn mmdb = %v", err)
	}
	mmdb := filepath.Join(dir, "openasn.mmdb")
	if err := os.WriteFile(mmdb, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenASNChecksum(dir); err == nil {
		t.Fatal("missing checksums should fail")
	}
	sums := filepath.Join(dir, "openasn-checksums.txt")
	if err := os.WriteFile(sums, []byte("deadbeef openasn.mmdb\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenASNChecksum(dir); err == nil {
		t.Fatal("bad checksum should fail")
	}
	got, _ := sha256File(mmdb)
	if err := os.WriteFile(sums, []byte(got+" openasn.mmdb\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenASNChecksum(dir); err != nil {
		t.Fatalf("valid checksum = %v", err)
	}
	if _, err := readChecksum(filepath.Join(dir, "missing"), "openasn.mmdb"); err == nil {
		t.Fatal("missing checksum file should fail")
	}
	if _, err := readChecksum(sums, "other"); err == nil {
		t.Fatal("missing checksum entry should fail")
	}
	if _, err := readChecksum(sums, "openasn.mmdb"); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureFileMetaWriteError(t *testing.T) {
	dir := t.TempDir()
	client := testHTTPClient(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, "payload", nil), nil
	})
	blocker := filepath.Join(dir, ".meta")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := ensureFile(context.Background(), client, "https://example.com", filepath.Join(dir, "file"), filepath.Join(blocker, "file.json"), nil, false)
	if err == nil {
		t.Fatal("meta write error should fail")
	}
}

func TestReadFileStateBadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileState(path); err == nil {
		t.Fatal("bad state JSON should fail")
	}
	if _, err := readFileState(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing state should fail")
	}
}

func TestFetchClientDefault(t *testing.T) {
	if c := fetchClient(); c == nil || c.Timeout == 0 {
		t.Fatalf("default fetch client = %+v", c)
	}
}

func TestFetchWithOptionsMkdirError(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := FetchWithOptions(context.Background(), filepath.Join(blocker, "raw"), FetchOptions{Exclude: excludeAllExcept()}); err == nil {
		t.Fatal("mkdir error should fail")
	}
}

func TestHeadRequestRetryNetwork(t *testing.T) {
	var calls int
	client := testHTTPClient(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("network")
		}
		return testResponse(http.StatusOK, "", nil), nil
	})
	if _, err := headRequest(context.Background(), client, "https://example.com"); err != nil || calls != 2 {
		t.Fatalf("network retry = %d, %v", calls, err)
	}
}

func TestDownloadConditionalRetries(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "file")
	var calls int
	client := testHTTPClient(func(*http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			return nil, errors.New("network")
		case 2:
			return testResponse(http.StatusInternalServerError, "", nil), nil
		default:
			return testResponse(http.StatusOK, "payload", nil), nil
		}
	})
	if res, err := downloadConditional(context.Background(), client, "https://example.com", dest, fileState{}); err != nil || !res.Changed {
		t.Fatalf("retry download = %+v, %v", res, err)
	}
	if calls != 3 {
		t.Fatalf("download calls = %d", calls)
	}

	noLength := testHTTPClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{}, Body: io.NopCloser(strings.NewReader("payload"))}, nil
	})
	res, err := downloadConditional(context.Background(), noLength, "https://example.com", dest, fileState{})
	if err != nil || res.State.ContentLength != 7 {
		t.Fatalf("content-length fallback = %+v, %v", res, err)
	}
}

func TestVerifyChecksumErrors(t *testing.T) {
	dir := t.TempDir()
	loop := filepath.Join(dir, "openasn.mmdb")
	if err := os.Symlink("openasn.mmdb", loop); err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenASNChecksum(dir); err == nil {
		t.Fatal("stat loop should fail")
	}

	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "openasn.mmdb"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "openasn-checksums.txt"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenASNChecksum(dir); err == nil {
		t.Fatal("checksum read error should fail")
	}

	dir = t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "openasn.mmdb"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openasn-checksums.txt"), []byte("deadbeef openasn.mmdb\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenASNChecksum(dir); err == nil {
		t.Fatal("mmdb hash error should fail")
	}
}
