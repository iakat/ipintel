package ipintel

import (
	"bytes"
	"encoding/json"
	"sort"
)

// rangeIndex finds the most specific network containing an address. OpenASN
// networks are normally non-overlapping, but the prefix-max index keeps the
// lookup correct (and cheap) even when nested ranges are present.
type rangeIndex struct {
	v4 []indexedRange
	v6 []indexedRange
}

type indexedRange struct {
	record Record
	maxEnd [16]byte
}

func newRangeIndex(records []Record) *rangeIndex {
	var v4, v6 []Record
	for _, r := range records {
		switch r.Family {
		case 4:
			v4 = append(v4, r)
		case 6:
			v6 = append(v6, r)
		}
	}
	return &rangeIndex{v4: buildRangeIndex(v4), v6: buildRangeIndex(v6)}
}

func buildRangeIndex(records []Record) []indexedRange {
	sort.Slice(records, func(i, j int) bool {
		if c := bytes.Compare(records[i].Start[:], records[j].Start[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(records[i].End[:], records[j].End[:]) < 0
	})
	out := make([]indexedRange, len(records))
	var max [16]byte
	for i, r := range records {
		if i == 0 || bytes.Compare(r.End[:], max[:]) > 0 {
			max = r.End
		}
		out[i] = indexedRange{record: r, maxEnd: max}
	}
	return out
}

func (idx *rangeIndex) find(family uint8, addr [16]byte) (Record, bool) {
	var ranges []indexedRange
	switch family {
	case 4:
		ranges = idx.v4
	case 6:
		ranges = idx.v6
	default:
		return Record{}, false
	}
	pos := sort.Search(len(ranges), func(i int) bool {
		return bytes.Compare(ranges[i].record.Start[:], addr[:]) > 0
	}) - 1
	var best Record
	found := false
	for i := pos; i >= 0 && bytes.Compare(ranges[i].maxEnd[:], addr[:]) >= 0; i-- {
		r := ranges[i].record
		if bytes.Compare(r.Start[:], addr[:]) > 0 || bytes.Compare(r.End[:], addr[:]) < 0 {
			continue
		}
		if !found || bytes.Compare(r.Start[:], best.Start[:]) > 0 ||
			(bytes.Equal(r.Start[:], best.Start[:]) && bytes.Compare(r.End[:], best.End[:]) < 0) {
			best, found = r, true
		}
	}
	return best, found
}

func detailObject(s string) map[string]any {
	out := map[string]any{}
	if s == "" {
		return out
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return map[string]any{}
	}
	return out
}

// deriveResidentialProxies promotes an open proxy to residential_proxy when
// the same address sits on an OpenASN residential or mobile network. The
// category is replaced rather than duplicated so a single signal cannot be
// counted twice by the noisy-OR scorer.
func deriveResidentialProxies(records []Record, openASNRecords []Record) {
	if len(openASNRecords) == 0 {
		return
	}
	idx := newRangeIndex(openASNRecords)
	for i := range records {
		r := &records[i]
		if r.Category != "proxy" {
			continue
		}
		network, ok := idx.find(r.Family, r.Start)
		if !ok {
			continue
		}
		detail := detailObject(r.Detail)
		detail["network_category"] = network.Category
		detail["network_confidence"] = network.Confidence
		if network.ASN != 0 {
			detail["asn"] = network.ASN
			if network.Org != "" {
				detail["org"] = network.Org
			}
		}
		switch network.Category {
		case "residential_isp":
			r.Category = "residential_proxy"
			if r.Confidence < 95 {
				r.Confidence = 95
			}
			detail["derived"] = "residential_proxy"
			detail["derived_from"] = "openasn"
		case "mobile":
			r.Category = "residential_proxy"
			if r.Confidence < 85 {
				r.Confidence = 85
			}
			detail["derived"] = "residential_proxy"
			detail["derived_from"] = "openasn"
		}
		if network.ASN != 0 {
			r.ASN = network.ASN
		}
		if network.Org != "" {
			r.Org = network.Org
		}
		r.Detail = detailJSON(detail)
	}
}
