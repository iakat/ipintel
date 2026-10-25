package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iakat/ipintel/ipintel"
)

func allExcept(names ...string) map[string]bool {
	keep := map[string]bool{}
	for _, name := range names {
		keep[name] = true
	}
	out := map[string]bool{}
	for _, name := range ipintel.SourceNames() {
		if !keep[name] {
			out[name] = true
		}
	}
	return out
}

func writeAWS(t *testing.T, dir, prefix string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aws-ip-ranges.json"), []byte(`{"prefixes":[{"ip_prefix":"`+prefix+`"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
}

func buildDB(t *testing.T, path, prefix string) {
	t.Helper()
	raw := t.TempDir()
	writeAWS(t, raw, prefix)
	if _, err := ipintel.Build(ipintel.BuildOptions{
		RawDir: raw, OutFile: path, Exclude: allExcept("aws"),
	}); err != nil {
		t.Fatal(err)
	}
}

func buildDBBytes(t *testing.T, prefix string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db")
	buildDB(t, path, prefix)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func withIO(t *testing.T) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	oldIn, oldOut, oldErr := stdin, stdout, stderr
	in := strings.NewReader("")
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	stdin, stdout, stderr = in, out, errOut
	t.Cleanup(func() { stdin, stdout, stderr = oldIn, oldOut, oldErr })
	return out, errOut
}

func TestMainAndRun(t *testing.T) {
	out, errOut := withIO(t)
	oldArgs, oldExit := os.Args, exit
	t.Cleanup(func() { os.Args, exit = oldArgs, oldExit })
	code := -1
	exit = func(c int) { code = c }
	os.Args = []string{"ip-intel", "sources"}
	main()
	if code != 0 || !strings.Contains(out.String(), "openasn") {
		t.Fatalf("main = %d, %q", code, out.String())
	}

	out.Reset()
	errOut.Reset()
	if code := run(nil); code != 2 || !strings.Contains(errOut.String(), "usage:") {
		t.Fatalf("run(nil) = %d %q", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"help"}); code != 0 || !strings.Contains(errOut.String(), "usage:") {
		t.Fatalf("run(help) = %d", code)
	}
	if code := run([]string{"nope"}); code != 2 || !strings.Contains(errOut.String(), "unknown command") {
		t.Fatalf("run(unknown) = %d %q", code, errOut.String())
	}

	db := filepath.Join(t.TempDir(), "db")
	buildDB(t, db, "1.2.3.0/24")
	raw := t.TempDir()
	writeAWS(t, raw, "1.2.4.0/24")
	for _, args := range [][]string{
		{"build", "--raw", raw, "--db", filepath.Join(t.TempDir(), "out"), "--exclude", excludedFlag()},
		{"query", "--db", db, "1.2.3.4"},
		{"fetch", "--out", t.TempDir(), "--no-build", "--exclude", allExcludedFlag()},
		{"serve", "--db", filepath.Join(t.TempDir(), "missing")},
		{"sources"},
	} {
		_ = run(args)
	}
}

func allExcludedFlag() string { return strings.Join(ipintel.SourceNames(), ",") }

func excludedFlag() string {
	names := make([]string, 0, len(ipintel.SourceNames()))
	for _, name := range ipintel.SourceNames() {
		if name != "aws" {
			names = append(names, name)
		}
	}
	return strings.Join(names, ",")
}

func TestListFlag(t *testing.T) {
	var l listFlag
	if l.String() != "" || len(l.set()) != 0 {
		t.Fatal("empty list flag")
	}
	if err := l.Set(" one, two ,,three "); err != nil {
		t.Fatal(err)
	}
	if got := l.String(); got != "one,two,three" {
		t.Fatalf("String = %q", got)
	}
	got := l.set()
	if len(got) != 3 || !got["one"] || !got["three"] {
		t.Fatalf("set = %+v", got)
	}
}

func TestEnvOr(t *testing.T) {
	old, set := os.LookupEnv("IPINTEL_TEST_ENV")
	t.Cleanup(func() {
		if set {
			os.Setenv("IPINTEL_TEST_ENV", old)
		} else {
			os.Unsetenv("IPINTEL_TEST_ENV")
		}
	})
	os.Unsetenv("IPINTEL_TEST_ENV")
	if got := envOr("IPINTEL_TEST_ENV", "fallback"); got != "fallback" {
		t.Fatalf("fallback = %q", got)
	}
	os.Setenv("IPINTEL_TEST_ENV", "value")
	if got := envOr("IPINTEL_TEST_ENV", "fallback"); got != "value" {
		t.Fatalf("value = %q", got)
	}
}

func TestBuildCommand(t *testing.T) {
	out, _ := withIO(t)
	raw := t.TempDir()
	writeAWS(t, raw, "1.2.3.0/24")
	db := filepath.Join(t.TempDir(), "db")
	if err := cmdBuild([]string{"--raw", raw, "--db", db, "--exclude", excludedFlag()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "built ") {
		t.Fatalf("build output = %q", out.String())
	}
	if err := cmdBuild([]string{"--raw", t.TempDir(), "--db", filepath.Join(t.TempDir(), "db"), "--exclude", "x4b-vpn"}); err == nil {
		t.Fatal("missing required source should fail")
	}
	if err := cmdBuild([]string{"--bad-flag"}); err == nil {
		t.Fatal("bad flag should fail")
	}
}

func TestQueryCommand(t *testing.T) {
	out, _ := withIO(t)
	db := filepath.Join(t.TempDir(), "db")
	buildDB(t, db, "1.2.3.0/24")
	if err := cmdQuery([]string{"--db", db, "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"ip": "1.2.3.4"`) {
		t.Fatalf("query output = %q", out.String())
	}
	out.Reset()
	if err := cmdQuery([]string{"--db", db, "1.2.3.4", "5.6.7.8"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "[") {
		t.Fatalf("multi query output = %q", out.String())
	}
	out.Reset()
	stdin = strings.NewReader("1.2.3.4\n\n")
	if err := cmdQuery([]string{"--db", db}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"ip": "1.2.3.4"`) {
		t.Fatalf("stdin query output = %q", out.String())
	}
	if err := cmdQuery([]string{"--db", db, "--in-memory", "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	stdin = strings.NewReader("")
	if err := cmdQuery([]string{"--db", db}); err == nil {
		t.Fatal("empty query should fail")
	}
	stdin = errReader{}
	if err := cmdQuery([]string{"--db", db}); err == nil {
		t.Fatal("stdin error should fail")
	}
	if err := cmdQuery([]string{"--db", db, "bad"}); err == nil {
		t.Fatal("bad IP should fail")
	}
	if err := cmdQuery([]string{"--db", filepath.Join(t.TempDir(), "missing"), "1.2.3.4"}); err == nil {
		t.Fatal("missing db should fail")
	}
	if err := cmdQuery([]string{"--bad-flag"}); err == nil {
		t.Fatal("bad flag should fail")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read") }

func TestFetchCommand(t *testing.T) {
	_, _ = withIO(t)
	old := notifyContext
	notifyContext = func(ctx context.Context, _ ...os.Signal) (context.Context, context.CancelFunc) {
		c, cancel := context.WithCancel(ctx)
		cancel()
		return c, cancel
	}
	t.Cleanup(func() { notifyContext = old })

	out := t.TempDir()
	if err := cmdFetch([]string{"--out", out, "--no-build", "--exclude", excludedFlag()}); err != nil {
		t.Fatal(err)
	}
	if err := cmdFetch([]string{"--out", out, "--update", "--no-build", "--exclude", excludedFlag()}); err == nil {
		t.Fatal("update without db should fail")
	}
	buildDB(t, filepath.Join(out, "ipintel.bin"), "1.2.3.0/24")
	if err := cmdFetch([]string{"--out", out, "--update", "--no-build", "--exclude", excludedFlag()}); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := cmdFetch([]string{"--out", filepath.Join(blocker, "out"), "--no-build", "--exclude", excludedFlag()}); err == nil {
		t.Fatal("mkdir error should fail")
	}
	buildOut := t.TempDir()
	writeAWS(t, filepath.Join(buildOut, "raw"), "1.2.3.0/24")
	if err := cmdFetch([]string{"--out", buildOut, "--exclude", excludedFlag()}); err != nil {
		t.Fatal(err)
	}
	if err := cmdFetch([]string{"--bad-flag"}); err == nil {
		t.Fatal("bad flag should fail")
	}
}

func TestServeCommand(t *testing.T) {
	_, _ = withIO(t)
	db := filepath.Join(t.TempDir(), "db")
	buildDB(t, db, "1.2.3.0/24")
	oldListen, oldNotify, oldReload := listenAndServe, notifyContext, startReload
	t.Cleanup(func() { listenAndServe, notifyContext, startReload = oldListen, oldNotify, oldReload })
	notifyContext = func(ctx context.Context, _ ...os.Signal) (context.Context, context.CancelFunc) {
		c, cancel := context.WithCancel(ctx)
		cancel()
		return c, cancel
	}
	startReload = func(string, time.Duration, *ipintel.Service, bool) {}
	listenAndServe = func(*http.Server) error { return http.ErrServerClosed }
	if err := cmdServe([]string{"--db", db, "--reload", "1m"}); err != nil {
		t.Fatalf("serve = %v", err)
	}
	if err := cmdServe([]string{"--db", db, "--in-memory"}); err != nil {
		t.Fatalf("in-memory serve = %v", err)
	}
	listenAndServe = func(*http.Server) error { return errors.New("listen") }
	if err := cmdServe([]string{"--db", db}); err == nil {
		t.Fatal("listen error should fail")
	}
	if err := cmdServe([]string{"--db", filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing db should fail")
	}
	if err := cmdServe([]string{"--bad-flag"}); err == nil {
		t.Fatal("bad flag should fail")
	}
}

func TestReloadLoop(t *testing.T) {
	oldTicker, oldAfter := reloadTicker, afterFunc
	t.Cleanup(func() { reloadTicker, afterFunc = oldTicker, oldAfter })
	ticks := make(chan time.Time, 1)
	ready := make(chan struct{})
	reloadTicker = func(time.Duration) (<-chan time.Time, func()) {
		close(ready)
		return ticks, func() {}
	}

	reloadLoop(context.Background(), filepath.Join(t.TempDir(), "missing"), time.Millisecond, ipintel.NewService(nil), false)

	dbPath := filepath.Join(t.TempDir(), "db")
	first := buildDBBytes(t, "1.2.3.0/24")
	second := buildDBBytes(t, "1.2.4.0/24")
	if err := os.WriteFile(dbPath, first, 0644); err != nil {
		t.Fatal(err)
	}
	db, err := ipintel.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := ipintel.NewService(db)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ready = make(chan struct{})
	reloadTicker = func(time.Duration) (<-chan time.Time, func()) { close(ready); return ticks, func() {} }
	go func() { reloadLoop(ctx, dbPath, time.Millisecond, svc, false); close(done) }()
	<-ready
	ticks <- time.Now()
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done

	// Changed file, old database present, afterFunc closes it.
	if err := os.WriteFile(dbPath, first, 0644); err != nil {
		t.Fatal(err)
	}
	db, err = ipintel.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	svc = ipintel.NewService(db)
	closed := make(chan struct{})
	afterFunc = func(_ time.Duration, f func()) *time.Timer {
		f()
		close(closed)
		return time.NewTimer(time.Hour)
	}
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	ready = make(chan struct{})
	reloadTicker = func(time.Duration) (<-chan time.Time, func()) { close(ready); return ticks, func() {} }
	go func() { reloadLoop(ctx, dbPath, time.Millisecond, svc, false); close(done) }()
	<-ready
	if err := os.WriteFile(dbPath, second, 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(dbPath, now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ticks <- time.Now()
	<-closed
	cancel()
	<-done

	// Changed file, in-memory database and open error.
	afterFunc = oldAfter
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	ready = make(chan struct{})
	reloadTicker = func(time.Duration) (<-chan time.Time, func()) { close(ready); return ticks, func() {} }
	go func() { reloadLoop(ctx, dbPath, time.Millisecond, ipintel.NewService(nil), true); close(done) }()
	<-ready
	os.WriteFile(dbPath, first, 0644)
	ticks <- time.Now()
	time.Sleep(5 * time.Millisecond)
	os.WriteFile(dbPath, []byte("bad"), 0644)
	ticks <- time.Now()
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done

	// Removed file after start.
	os.WriteFile(dbPath, first, 0644)
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	ready = make(chan struct{})
	reloadTicker = func(time.Duration) (<-chan time.Time, func()) { close(ready); return ticks, func() {} }
	go func() { reloadLoop(ctx, dbPath, time.Millisecond, ipintel.NewService(nil), false); close(done) }()
	<-ready
	os.Remove(dbPath)
	ticks <- time.Now()
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done
}

func TestDefaults(t *testing.T) {
	oldListen, oldReload, oldTicker := listenAndServe, startReload, reloadTicker
	t.Cleanup(func() { listenAndServe, startReload, reloadTicker = oldListen, oldReload, oldTicker })
	listenAndServe, startReload, reloadTicker = oldListen, oldReload, oldTicker
	if err := listenAndServe(&http.Server{Addr: "bad"}); err == nil {
		t.Fatal("bad listen address should fail")
	}
	startReload(filepath.Join(t.TempDir(), "missing"), time.Millisecond, ipintel.NewService(nil), false)
	ch, stop := reloadTicker(time.Millisecond)
	if ch == nil || stop == nil {
		t.Fatal("default reload ticker")
	}
	stop()
}
