package ipintel

import (
	"math"
	"sort"
)

// Category weights are deliberately not "abuse" weights. They describe how
// strongly a signal says "this is not an ordinary residential eyeball
// connection". A datacenter alone is a weak signal; Tor is the strongest.
var categoryWeights = map[string]int{
	"tor":                100,
	"residential_proxy":  95,
	"vpn":                80,
	"vpn_candidate":      0,
	"proxy":              70,
	"relay":              50,
	"hosting":            45,
	"enterprise_gateway": 35,
	"cdn":                20,
	"business":           10,
	"mobile":             5,
	"education":          5,
	"government":         5,
	"residential_isp":    0,
	"unknown":            0,
	"info":               0,
	"country":            0,
}

var categoryOrder = []string{
	"tor", "residential_proxy", "vpn", "vpn_candidate", "proxy", "relay", "hosting",
	"enterprise_gateway", "cdn", "business", "mobile", "education",
	"government", "residential_isp", "unknown",
}

func scoringWeights() map[string]int {
	out := make(map[string]int, len(categoryWeights))
	for k, v := range categoryWeights {
		out[k] = v
	}
	return out
}

func categoryRank(cat string) int {
	for i, c := range categoryOrder {
		if c == cat {
			return i
		}
	}
	return len(categoryOrder)
}

// scoreEvidence combines categories with a noisy-OR. The maximum confidence
// per category is used so that several sources saying the same thing do not
// inflate the score; independent categories do reinforce each other.
func scoreEvidence(evidence []Evidence) (score int, verdict string, categories []CategoryScore) {
	maxConf := map[string]int{}
	for _, e := range evidence {
		cat := e.Category
		if cat == "" {
			cat = "unknown"
		}
		if _, ok := categoryWeights[cat]; !ok {
			continue
		}
		c := e.Confidence
		if c < 0 {
			c = 0
		}
		if c > 100 {
			c = 100
		}
		if c > maxConf[cat] {
			maxConf[cat] = c
		}
	}

	product := 1.0
	for cat, conf := range maxConf {
		weight := categoryWeights[cat]
		if weight == 0 || conf == 0 {
			continue
		}
		catScore := float64(weight*conf) / 100.0
		product *= 1.0 - catScore/100.0
		categories = append(categories, CategoryScore{
			Category: cat, Confidence: conf, Score: int(math.Round(catScore)),
		})
	}
	sort.Slice(categories, func(i, j int) bool {
		if categories[i].Score != categories[j].Score {
			return categories[i].Score > categories[j].Score
		}
		return categoryRank(categories[i].Category) < categoryRank(categories[j].Category)
	})
	if len(categories) > 0 {
		verdict = categories[0].Category
	} else {
		verdict = "unknown"
	}
	score = int(math.Round(100 * (1 - product)))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, verdict, categories
}
