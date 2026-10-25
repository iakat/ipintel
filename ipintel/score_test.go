package ipintel

import (
	"math"
	"testing"
)

func TestScoreEvidence(t *testing.T) {
	tests := []struct {
		name    string
		ev      []Evidence
		score   int
		verdict string
	}{
		{"empty", nil, 0, "unknown"},
		{"tor", []Evidence{{Category: "tor", Confidence: 100, Matched: true}}, 100, "tor"},
		{"hosting", []Evidence{{Category: "hosting", Confidence: 80, Matched: true}}, 36, "hosting"},
		{"vpn", []Evidence{{Category: "vpn", Confidence: 85, Matched: true}}, 68, "vpn"},
		{"vpn+hosting", []Evidence{
			{Category: "vpn", Confidence: 85, Matched: true},
			{Category: "hosting", Confidence: 80, Matched: true},
		}, 80, "vpn"},
		{"candidate ignored", []Evidence{
			{Category: "vpn_candidate", Confidence: 60, Matched: true},
			{Category: "hosting", Confidence: 80, Matched: true},
		}, 36, "hosting"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score, verdict, _ := scoreEvidence(tc.ev)
			if score != tc.score || verdict != tc.verdict {
				t.Fatalf("score/verdict = %d/%s, want %d/%s", score, verdict, tc.score, tc.verdict)
			}
		})
	}
}

func TestScoreNeverExceedsHundred(t *testing.T) {
	ev := []Evidence{
		{Category: "tor", Confidence: 100, Matched: true},
		{Category: "vpn", Confidence: 100, Matched: true},
		{Category: "proxy", Confidence: 100, Matched: true},
		{Category: "relay", Confidence: 100, Matched: true},
		{Category: "hosting", Confidence: 100, Matched: true},
	}
	score, _, _ := scoreEvidence(ev)
	if score > 100 || score != 100 {
		t.Fatalf("score = %d, want 100", score)
	}
}

func TestScoreRounds(t *testing.T) {
	score, _, _ := scoreEvidence([]Evidence{{Category: "hosting", Confidence: 50, Matched: true}})
	if math.Round(float64(score)) != float64(score) {
		t.Fatalf("score is not an integer: %d", score)
	}
}

func TestCategoryRank(t *testing.T) {
	for i, cat := range categoryOrder {
		if got := categoryRank(cat); got != i {
			t.Errorf("categoryRank(%q) = %d, want %d", cat, got, i)
		}
	}
	if got := categoryRank("not-a-category"); got != len(categoryOrder) {
		t.Errorf("unknown rank = %d", got)
	}
}

func TestScoreClampsAndSorts(t *testing.T) {
	oldVPN := categoryWeights["vpn"]
	categoryWeights["vpn"] = 200
	score, verdict, _ := scoreEvidence([]Evidence{{Category: "vpn", Confidence: 100}})
	categoryWeights["vpn"] = oldVPN
	if score != 100 || verdict != "vpn" {
		t.Fatalf("upper clamp = %d/%s", score, verdict)
	}

	oldHosting := categoryWeights["hosting"]
	categoryWeights["hosting"] = -100
	score, _, _ = scoreEvidence([]Evidence{{Category: "hosting", Confidence: 100}})
	categoryWeights["hosting"] = oldHosting
	if score != 0 {
		t.Fatalf("lower clamp = %d", score)
	}

	// Equal scores fall back to categoryOrder, not input order.
	_, _, cats := scoreEvidence([]Evidence{
		{Category: "hosting", Confidence: 100},
		{Category: "vpn", Confidence: 56}, // 45 vs 45 after rounding
	})
	if len(cats) != 2 || cats[0].Category != "vpn" {
		t.Fatalf("tie sort = %+v", cats)
	}

	// A zero confidence weighted category must not be added.
	_, _, cats = scoreEvidence([]Evidence{{Category: "vpn", Confidence: 0}})
	if len(cats) != 0 {
		t.Fatalf("zero confidence categories = %+v", cats)
	}

	// Unknown and empty categories are ignored.
	_, _, cats = scoreEvidence([]Evidence{
		{Category: "not-real", Confidence: 100},
		{Category: "unknown", Confidence: 100},
		{Category: "vpn", Confidence: -10},
		{Category: "hosting", Confidence: 200},
	})
	if len(cats) != 1 || cats[0].Category != "hosting" || cats[0].Confidence != 100 {
		t.Fatalf("clamped categories = %+v", cats)
	}
}
