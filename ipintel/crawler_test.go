package ipintel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePrefixJSON(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "bots.json", `{"prefixes":[
		{"ipv4Prefix":"66.249.64.0/27"},
		{"ipv6Prefix":"2001:4860:4801:10::/64"},
		{"ipv4Prefix":"192.178.4.0/27","ipv6Prefix":"2001:db8::/32"},
		{"neither":true},
		{}
	]}`)
	got, err := parsePrefixJSON(dir, []string{"bots.json"}, "search_crawler", 100, map[string]any{"bot": "TestBot"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 4 {
		t.Fatalf("records = %d, want 4", len(got.Records))
	}
	for _, rec := range got.Records {
		if rec.Category != "search_crawler" || rec.Confidence != 100 {
			t.Fatalf("record = %+v", rec)
		}
		if !strings.Contains(rec.Detail, `"bot":"TestBot"`) {
			t.Fatalf("detail = %s", rec.Detail)
		}
	}
	// Empty prefix strings are skipped rather than parsed as an invalid CIDR.
	writeTestFile(t, dir, "blank.json", `{"prefixes":[{"ipv4Prefix":"  "},{"ipv6Prefix":""}]}`)
	blank, err := parsePrefixJSON(dir, []string{"blank.json"}, "ai_crawler", 100, nil)
	if err != nil || len(blank.Records) != 0 {
		t.Fatalf("blank prefixes = %+v, %v", blank.Records, err)
	}
}

func TestParsePrefixJSONErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := parsePrefixJSON(dir, []string{"missing.json"}, "ai_crawler", 100, nil); err == nil {
		t.Fatal("missing file should fail")
	}
	writeTestFile(t, dir, "bad.json", "{")
	if _, err := parsePrefixJSON(dir, []string{"bad.json"}, "ai_crawler", 100, nil); err == nil {
		t.Fatal("bad JSON should fail")
	}
	writeTestFile(t, dir, "badcidr.json", `{"prefixes":[{"ipv4Prefix":"not-a-cidr"}]}`)
	if _, err := parsePrefixJSON(dir, []string{"badcidr.json"}, "ai_crawler", 100, nil); err == nil {
		t.Fatal("bad CIDR should fail")
	}
}

func TestParseBotRanges(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "bot.json", `{"prefixes":[{"ipv4Prefix":"66.249.64.0/27"}]}`)
	got, err := parseBotRanges("ai_crawler", "OpenAI", "GPTBot")(dir, []string{"bot.json"})
	if err != nil || len(got.Records) != 1 {
		t.Fatalf("bot parse = %+v, %v", got, err)
	}
	detail := got.Records[0].Detail
	for _, want := range []string{`"operator":"OpenAI"`, `"bot":"GPTBot"`, `"group":"crawlers"`, `"cidr":"66.249.64.0/27"`} {
		if !strings.Contains(detail, want) {
			t.Fatalf("detail %s missing %s", detail, want)
		}
	}
}

func TestCrawlerSources(t *testing.T) {
	specs := sourceSpecs(Options{})
	crawlers := map[string]string{
		"googlebot":              "search_crawler",
		"google-special-crawler": "search_crawler",
		"bingbot":                "search_crawler",
		"applebot":               "search_crawler",
		"gptbot":                 "ai_crawler",
		"openai-searchbot":       "ai_crawler",
		"chatgpt-user":           "ai_crawler",
		"perplexitybot":          "ai_crawler",
		"ccbot":                  "ai_crawler",
	}
	seen := map[string]bool{}
	for _, spec := range specs {
		want, ok := crawlers[spec.Name]
		if !ok {
			continue
		}
		seen[spec.Name] = true
		if spec.Group != "crawlers" {
			t.Errorf("%s group = %q, want crawlers", spec.Name, spec.Group)
		}
		if !spec.Optional {
			t.Errorf("%s must be optional", spec.Name)
		}
		if spec.Parse == nil || len(spec.Files) != 1 {
			t.Errorf("%s spec = %+v", spec.Name, spec)
		}
		dir := t.TempDir()
		writeTestFile(t, dir, spec.Files[0].Name, `{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`)
		parsed, err := spec.Parse(dir, []string{spec.Files[0].Name})
		if err != nil || len(parsed.Records) != 1 {
			t.Fatalf("%s parse = %+v, %v", spec.Name, parsed, err)
		}
		if got := parsed.Records[0].Category; got != want {
			t.Errorf("%s category = %q, want %q", spec.Name, got, want)
		}
	}
	for name := range crawlers {
		if !seen[name] {
			t.Errorf("crawler source %q is missing", name)
		}
	}

	// The group name works as an --exclude shorthand.
	excluded := sourceSpecs(Options{Exclude: map[string]bool{"crawlers": true}})
	for _, spec := range excluded {
		if spec.Group == "crawlers" {
			t.Errorf("%s still present when the crawlers group is excluded", spec.Name)
		}
	}
	if len(excluded) != len(specs)-len(crawlers) {
		t.Errorf("group exclude kept %d sources, want %d", len(excluded), len(specs)-len(crawlers))
	}
}

func TestCrawlerCategoriesAreScoreNeutral(t *testing.T) {
	for _, cat := range []string{"search_crawler", "ai_crawler"} {
		if w, ok := categoryWeights[cat]; !ok || w != 0 {
			t.Fatalf("%s weight = %d, %v; want 0", cat, w, ok)
		}
		if categoryRank(cat) >= len(categoryOrder) {
			t.Fatalf("%s is not in categoryOrder", cat)
		}
	}
	score, verdict, cats := scoreEvidence([]Evidence{
		{Source: "googlebot", Category: "search_crawler", Confidence: 100, Matched: true},
	})
	if score != 0 || verdict != "unknown" || len(cats) != 0 {
		t.Fatalf("crawler-only score/verdict/categories = %d/%s/%+v", score, verdict, cats)
	}
	// A crawler on a hosting range must not subtract from the hosting score.
	score, verdict, _ = scoreEvidence([]Evidence{
		{Source: "googlebot", Category: "search_crawler", Confidence: 100, Matched: true},
		{Source: "x4b-datacenter", Category: "hosting", Confidence: 80, Matched: true},
	})
	if score != 36 || verdict != "hosting" {
		t.Fatalf("crawler+hosting = %d/%s, want 36/hosting", score, verdict)
	}
}

func TestBuildCrawlerSource(t *testing.T) {
	raw := t.TempDir()
	for _, name := range []string{"googlebot-common.json", "gptbot.json"} {
		if err := os.WriteFile(filepath.Join(raw, name), []byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`), 0644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "db.bin")
	m, err := Build(BuildOptions{
		RawDir: raw, OutFile: out, Exclude: excludeAllExcept("googlebot", "gptbot"), BlockSize: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Sources) != 2 {
		t.Fatalf("sources = %+v", m.Sources)
	}
	groups := map[string]string{}
	for _, s := range m.Sources {
		groups[s.Name] = s.Group
	}
	if groups["googlebot"] != "crawlers" || groups["gptbot"] != "crawlers" {
		t.Fatalf("manifest groups = %+v", groups)
	}

	db, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Lookup("192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if res.Score != 0 || res.Verdict != "unknown" {
		t.Fatalf("crawler lookup score/verdict = %d/%s", res.Score, res.Verdict)
	}
	found := map[string]string{}
	for _, ev := range res.Evidence {
		if ev.Matched {
			found[ev.Source] = ev.Category
		}
	}
	if found["googlebot"] != "search_crawler" || found["gptbot"] != "ai_crawler" {
		t.Fatalf("crawler evidence = %+v", found)
	}
}

func TestBuildCrawlerGroupFromBase(t *testing.T) {
	// A base database keeps the group when the raw file is gone, which is the
	// path used by fetch --update.
	base := filepath.Join(t.TempDir(), "base.bin")
	rec := testRecord(t, "192.0.2.0/24", 0, "ai_crawler", 100, 0, "", "", `{"bot":"GPTBot"}`)
	if err := writeDatabase(base, []Record{rec}, &Manifest{
		FormatVersion: FormatVersion, BlockSize: 8,
		Sources: []SourceMeta{{ID: 0, Name: "gptbot"}},
	}); err != nil {
		t.Fatal(err)
	}
	m, err := Build(BuildOptions{
		RawDir: t.TempDir(), OutFile: filepath.Join(t.TempDir(), "out"),
		BaseDB: base, Exclude: excludeAllExcept("gptbot"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Sources) != 1 || m.Sources[0].Group != "crawlers" || m.Sources[0].Optional != true {
		t.Fatalf("base crawler source = %+v", m.Sources)
	}
}
