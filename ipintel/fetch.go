package ipintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type fileState struct {
	URL           string    `json:"url"`
	ETag          string    `json:"etag,omitempty"`
	LastModified  string    `json:"last_modified,omitempty"`
	ContentLength int64     `json:"content_length,omitempty"`
	SHA256        string    `json:"sha256,omitempty"`
	Bytes         int64     `json:"bytes,omitempty"`
	FetchedAt     time.Time `json:"fetched_at"`
}

type headInfo struct {
	ETag          string
	LastModified  string
	ContentLength int64
	Status        int
}

type fetchResult struct {
	Changed bool
	State   fileState
}

var (
	fetchClient = func() *http.Client {
		return &http.Client{Timeout: 10 * time.Minute}
	}
	retryBase = 500 * time.Millisecond
)

// FetchOptions controls FetchWithOptions.
type FetchOptions struct {
	Exclude      map[string]bool
	Parallel     int
	Base         *Manifest // validators from an existing database
	AllowMissing bool      // skip unchanged files even when the raw copy is gone
}

// Fetch downloads every selected source file into rawDir. Kept for callers
// that only need the default parallel fetch.
func Fetch(ctx context.Context, rawDir string, opts Options) error {
	return FetchWithOptions(ctx, rawDir, FetchOptions{Exclude: opts.Exclude})
}

// FetchWithOptions downloads selected sources in parallel. HEAD is used first;
// when the validators (ETag / Last-Modified, with a size fallback) match the
// local file or the base database metadata, the file is not downloaded again.
func FetchWithOptions(ctx context.Context, rawDir string, opts FetchOptions) error {
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return err
	}
	if opts.Parallel <= 0 {
		opts.Parallel = 6
	}
	if opts.Parallel > 32 {
		opts.Parallel = 32
	}
	specs := sourceSpecs(Options{Exclude: opts.Exclude})
	baseFiles := manifestFiles(opts.Base)
	client := fetchClient()

	type task struct {
		spec sourceSpec
		file fetchFile
		base *FileMeta
	}
	var tasks []task
	for _, spec := range specs {
		for _, file := range spec.Files {
			t := task{spec: spec, file: file}
			if meta, ok := baseFiles[file.Name]; ok && meta.URL == file.URL {
				m := meta
				t.base = &m
			}
			tasks = append(tasks, t)
		}
	}
	type outcome struct {
		changed bool
		err     error
	}
	outcomes := make([]outcome, len(tasks))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < opts.Parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				t := tasks[i]
				dest := filepath.Join(rawDir, t.file.Name)
				meta := filepath.Join(rawDir, ".meta", t.file.Name+".json")
				changed, err := ensureFile(ctx, client, t.file.URL, dest, meta, t.base, opts.AllowMissing)
				outcomes[i] = outcome{changed: changed, err: err}
			}
		}()
	}
	for i := range tasks {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	for i, t := range tasks {
		fmt.Printf("  %-30s ", t.file.Name)
		o := outcomes[i]
		if o.err != nil {
			if t.spec.Optional {
				fmt.Printf("optional, skipped: %v\n", o.err)
				continue
			}
			fmt.Println("FAILED")
			return fmt.Errorf("%s: %w", t.file.Name, o.err)
		}
		if !o.changed {
			fmt.Println("unchanged")
			continue
		}
		if st, err := os.Stat(filepath.Join(rawDir, t.file.Name)); err == nil {
			fmt.Printf("%d bytes\n", st.Size())
		}
	}
	return verifyOpenASNChecksum(rawDir)
}

func manifestFiles(m *Manifest) map[string]FileMeta {
	out := map[string]FileMeta{}
	if m == nil {
		return out
	}
	for _, source := range m.Sources {
		for _, file := range source.Files {
			out[file.Name] = file
		}
	}
	return out
}

func ensureFile(ctx context.Context, client *http.Client, sourceURL, dest, metaPath string, base *FileMeta, allowMissing bool) (bool, error) {
	state, _ := readFileState(metaPath)
	local, statErr := os.Stat(dest)
	haveLocal := statErr == nil && local.Size() > 0
	if (!haveLocal || state.URL != sourceURL) && allowMissing && base != nil && base.URL == sourceURL {
		state = fileState{
			URL: base.URL, ETag: base.ETag, LastModified: base.LastModified,
			ContentLength: base.Bytes, SHA256: base.SHA256, Bytes: base.Bytes, FetchedAt: base.FetchedAt,
		}
	}
	localSize := int64(0)
	if haveLocal {
		localSize = local.Size()
	}

	head, headErr := headRequest(ctx, client, sourceURL)
	if headErr == nil && head.Status == http.StatusOK && state.URL == sourceURL &&
		(haveLocal || (allowMissing && base != nil)) {
		if stateMatches(state, head, localSize) {
			return false, nil
		}
	}

	res, err := downloadConditional(ctx, client, sourceURL, dest, state)
	if err != nil {
		return false, err
	}
	if !res.Changed {
		return false, nil
	}
	if err := writeFileState(metaPath, res.State); err != nil {
		return true, err
	}
	return true, nil
}

func stateMatches(state fileState, head headInfo, localSize int64) bool {
	if state.URL == "" {
		return false
	}
	if head.ETag != "" && state.ETag == head.ETag {
		return true
	}
	if head.LastModified != "" && state.LastModified == head.LastModified {
		return true
	}
	// Servers that expose neither validator get a conservative size check.
	if head.ETag == "" && head.LastModified == "" && head.ContentLength > 0 &&
		state.ContentLength == head.ContentLength &&
		(localSize == 0 || localSize == head.ContentLength) {
		return true
	}
	return false
}

func headRequest(ctx context.Context, client *http.Client, sourceURL string) (headInfo, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return headInfo{}, ctx.Err()
			case <-time.After(time.Duration(attempt) * retryBase):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, sourceURL, nil)
		if err != nil {
			return headInfo{}, err
		}
		req.Header.Set("User-Agent", "ip-intel/1")
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		info := headInfo{
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
			Status:       resp.StatusCode,
		}
		if resp.ContentLength > 0 {
			info.ContentLength = resp.ContentLength
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return info, nil
		}
		last = fmt.Errorf("HEAD %s", resp.Status)
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			break
		}
	}
	return headInfo{}, last
}

func downloadConditional(ctx context.Context, client *http.Client, sourceURL, dest string, state fileState) (fetchResult, error) {
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fetchResult{}, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * retryBase):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
		if err != nil {
			return fetchResult{}, err
		}
		req.Header.Set("User-Agent", "ip-intel/1")
		if state.ETag != "" {
			req.Header.Set("If-None-Match", state.ETag)
		}
		if state.LastModified != "" {
			req.Header.Set("If-Modified-Since", state.LastModified)
		} else if !state.FetchedAt.IsZero() {
			req.Header.Set("If-Modified-Since", state.FetchedAt.UTC().Format(http.TimeFormat))
		}
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			return fetchResult{Changed: false}, nil
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			last = fmt.Errorf("HTTP %s", resp.Status)
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return fetchResult{}, last
			}
			continue
		}
		tmp := dest + ".part"
		f, err := os.Create(tmp)
		if err != nil {
			resp.Body.Close()
			return fetchResult{}, err
		}
		h := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(f, h), resp.Body)
		closeErr := f.Close()
		resp.Body.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
		if copyErr != nil {
			os.Remove(tmp)
			last = copyErr
			continue
		}
		if n == 0 {
			os.Remove(tmp)
			last = fmt.Errorf("empty response")
			continue
		}
		if err := os.Rename(tmp, dest); err != nil {
			os.Remove(tmp)
			return fetchResult{}, err
		}
		contentLength := resp.ContentLength
		if contentLength <= 0 {
			contentLength = n
		}
		return fetchResult{Changed: true, State: fileState{
			URL:           sourceURL,
			ETag:          resp.Header.Get("ETag"),
			LastModified:  resp.Header.Get("Last-Modified"),
			ContentLength: contentLength,
			SHA256:        hex.EncodeToString(h.Sum(nil)),
			Bytes:         n,
			FetchedAt:     time.Now().UTC(),
		}}, nil
	}
	return fetchResult{}, last
}

func readFileState(path string) (fileState, error) {
	var s fileState
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}

func writeFileState(path string, state fileState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(state, "", "  ")
	tmp := path + ".part"
	if err := os.WriteFile(tmp, append(b, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyOpenASNChecksum(rawDir string) error {
	mmdb := filepath.Join(rawDir, "openasn.mmdb")
	sums := filepath.Join(rawDir, "openasn-checksums.txt")
	if _, err := os.Stat(mmdb); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if _, err := os.Stat(sums); err != nil {
		return fmt.Errorf("openasn checksum file missing: %w", err)
	}
	want, err := readChecksum(sums, "openasn.mmdb")
	if err != nil {
		return err
	}
	got, err := sha256File(mmdb)
	if err != nil {
		return err
	}
	if !strings.EqualFold(want, got) {
		return fmt.Errorf("openasn.mmdb checksum mismatch: want %s, got %s", want, got)
	}
	return nil
}

func readChecksum(path, name string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == name {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("%s not found in %s", name, path)
}
