package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/iakat/ipintel/ipintel"
)

var (
	stdin          io.Reader = os.Stdin
	stdout         io.Writer = os.Stdout
	stderr         io.Writer = os.Stderr
	exit                     = os.Exit
	notifyContext            = signal.NotifyContext
	listenAndServe           = func(s *http.Server) error { return s.ListenAndServe() }
	startReload              = func(path string, every time.Duration, svc *ipintel.Service, inMemory bool) {
		go reloadLoop(context.Background(), path, every, svc, inMemory)
	}
	reloadTicker = func(every time.Duration) (<-chan time.Time, func()) {
		t := time.NewTicker(every)
		return t.C, t.Stop
	}
	afterFunc = time.AfterFunc
)

func main() {
	exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	var err error
	switch args[0] {
	case "fetch":
		err = cmdFetch(args[1:])
	case "build":
		err = cmdBuild(args[1:])
	case "query":
		err = cmdQuery(args[1:])
	case "serve":
		err = cmdServe(args[1:])
	case "sources":
		for _, name := range ipintel.SourceNames() {
			fmt.Fprintln(stdout, name)
		}
		return 0
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage()
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprint(stderr, `ip-intel - local IP intelligence from static files

usage:
  ip-intel fetch [--out DIR] [--exclude SOURCE] [--update] [--parallel N] [--no-build]
  ip-intel build [--raw DIR] [--db FILE] [--base-db FILE] [--exclude SOURCE]
  ip-intel query [--db FILE] [--in-memory] IP...
  ip-intel serve [--db FILE] [--addr :8080] [--reload 1m] [--in-memory]
  ip-intel sources

fetch downloads all sources by default, then builds the compressed database.
Use --exclude (repeatable or comma-separated) to leave sources out.
--update reuses records from the existing DB for sources whose raw files are
missing or unchanged; it still downloads every changed source.
build rebuilds the database from an existing raw directory.
query prints the full evidence and combined score as JSON.
serve exposes GET /v1/lookup?ip=... and GET /v1/lookup/<ip>.
sources lists the names accepted by --exclude.
`)
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

func (l listFlag) set() map[string]bool {
	out := make(map[string]bool, len(l))
	for _, name := range l {
		out[name] = true
	}
	return out
}

func cmdFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "./data", "output directory")
	var exclude listFlag
	fs.Var(&exclude, "exclude", "source to exclude (repeatable or comma-separated)")
	noBuild := fs.Bool("no-build", false, "only download raw files")
	update := fs.Bool("update", false, "reuse unchanged/missing sources from the existing DB")
	parallel := fs.Int("parallel", 6, "parallel downloads (1-32)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw := filepath.Join(*out, "raw")
	dbPath := filepath.Join(*out, "ipintel.bin")
	opts := ipintel.Options{Exclude: exclude.set()}
	fopts := ipintel.FetchOptions{Exclude: opts.Exclude, Parallel: *parallel}
	baseDB := ""
	if *update {
		base, err := ipintel.Open(dbPath)
		if err != nil {
			return fmt.Errorf("--update needs an existing database at %s: %w", dbPath, err)
		}
		m := base.Manifest()
		base.Close()
		fopts.Base = &m
		fopts.AllowMissing = true
		baseDB = dbPath
	}
	ctx, cancel := notifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.Printf("fetching raw sources into %s", raw)
	if err := ipintel.FetchWithOptions(ctx, raw, fopts); err != nil {
		return err
	}
	if *noBuild {
		return nil
	}
	return build(raw, dbPath, opts, ipintel.DefaultBlock, baseDB)
}

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(stderr)
	raw := fs.String("raw", "./data/raw", "raw source directory")
	db := fs.String("db", "./data/ipintel.bin", "output database")
	var exclude listFlag
	fs.Var(&exclude, "exclude", "source to exclude (repeatable or comma-separated)")
	block := fs.Int("block-size", ipintel.DefaultBlock, "records per zstd block")
	baseDB := fs.String("base-db", "", "reuse unchanged/missing sources from this database")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts := ipintel.Options{Exclude: exclude.set()}
	return build(*raw, *db, opts, *block, *baseDB)
}

func build(raw, db string, opts ipintel.Options, block int, baseDB string) error {
	m, err := ipintel.Build(ipintel.BuildOptions{
		RawDir: raw, OutFile: db, BaseDB: baseDB, Exclude: opts.Exclude, BlockSize: block,
	})
	if err != nil {
		return err
	}
	st, _ := os.Stat(db)
	size := int64(0)
	if st != nil {
		size = st.Size()
	}
	fmt.Fprintf(stdout, "built %s: %d records, %d blocks, %d sources, %.1f MB\n",
		db, m.RecordCount, m.BlockCount, len(m.Sources), float64(size)/(1024*1024))
	return nil
}

func cmdQuery(args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "./data/ipintel.bin", "database file")
	inMemory := fs.Bool("in-memory", false, "load the whole database into RAM")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ips := fs.Args()
	if len(ips) == 0 {
		sc := bufio.NewScanner(stdin)
		for sc.Scan() {
			if s := strings.TrimSpace(sc.Text()); s != "" {
				ips = append(ips, s)
			}
		}
		if err := sc.Err(); err != nil {
			return err
		}
	}
	if len(ips) == 0 {
		return errors.New("no IP given")
	}
	var db *ipintel.DB
	var err error
	if *inMemory {
		db, err = ipintel.OpenInMemory(*dbPath)
	} else {
		db, err = ipintel.Open(*dbPath)
	}
	if err != nil {
		return err
	}
	defer db.Close()

	results := make([]ipintel.Result, 0, len(ips))
	for _, ip := range ips {
		res, err := db.Lookup(ip)
		if err != nil {
			return err
		}
		results = append(results, res)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if len(results) == 1 {
		return enc.Encode(results[0])
	}
	return enc.Encode(results)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", envOr("IPINTEL_DB", "./data/ipintel.bin"), "database file")
	addr := fs.String("addr", envOr("IPINTEL_ADDR", ":8080"), "listen address")
	reload := fs.Duration("reload", time.Minute, "reload the database when the file changes; 0 disables")
	inMemory := fs.Bool("in-memory", false, "load the whole database into RAM")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var db *ipintel.DB
	var err error
	if *inMemory {
		db, err = ipintel.OpenInMemory(*dbPath)
	} else {
		db, err = ipintel.Open(*dbPath)
	}
	if err != nil {
		return err
	}
	svc := ipintel.NewService(db)
	if *reload > 0 {
		startReload(*dbPath, *reload, svc, *inMemory)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           svc.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	ctx, stop := notifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("ip-intel listening on %s (db %s)", *addr, *dbPath)
	err = listenAndServe(srv)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func reloadLoop(ctx context.Context, path string, every time.Duration, svc *ipintel.Service, inMemory bool) {
	st, err := os.Stat(path)
	if err != nil {
		log.Printf("reload: %v", err)
		return
	}
	lastMod, lastSize := st.ModTime(), st.Size()
	ticks, stop := reloadTicker(every)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
		st, err := os.Stat(path)
		if err != nil || (st.ModTime().Equal(lastMod) && st.Size() == lastSize) {
			continue
		}
		var next *ipintel.DB
		if inMemory {
			next, err = ipintel.OpenInMemory(path)
		} else {
			next, err = ipintel.Open(path)
		}
		if err != nil {
			log.Printf("reload: %v", err)
			continue
		}
		old := svc.Swap(next)
		lastMod, lastSize = st.ModTime(), st.Size()
		log.Printf("reloaded %s (%d records)", path, next.Manifest().RecordCount)
		if old != nil {
			afterFunc(30*time.Second, func() { _ = old.Close() })
		}
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
