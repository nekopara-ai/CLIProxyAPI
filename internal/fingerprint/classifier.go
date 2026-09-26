// Package fingerprint implements reference-bank classification, not model identity attestation.
package fingerprint

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"unicode"
)

//go:embed data/unified_bank.json
var embeddedBank []byte

type modelProfile struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}
type artifact struct {
	Mean         []float64     `json:"feature_mean"`
	Scale        []float64     `json:"feature_scale"`
	Basis        [][]float64   `json:"nuisance_basis"`
	Centroids    [][]float64   `json:"centroids"`
	Environments [][][]float64 `json:"environment_centroids"`
	Weight       float64       `json:"weight"`
}
type Bank struct {
	Models []modelProfile `json:"models"`
	Robust struct {
		Hellinger artifact `json:"hellinger"`
		Ordered   artifact `json:"ordered_blocks"`
	} `json:"robust"`
	Calibration map[string]struct {
		Beta float64 `json:"beta"`
	} `json:"calibration"`
	Version string `json:"-"`
}
type Answer struct {
	Text          string `json:"text,omitempty"`
	ExpectedCount int    `json:"expected_count"`
}
type Candidate struct {
	Model       string  `json:"model"`
	Probability float64 `json:"probability"`
}
type Classification struct {
	Prediction    string      `json:"prediction,omitempty"`
	Probability   *float64    `json:"probability,omitempty"`
	UsedOutputs   int         `json:"used_outputs"`
	ParsedNumbers []int       `json:"parsed_numbers"`
	Candidates    []Candidate `json:"candidates,omitempty"`
	BankVersion   string      `json:"bank_version"`
}

func LoadBank(path string) (*Bank, error) {
	raw := embeddedBank
	var err error
	if path != "" {
		raw, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("fingerprint reference bank could not be read")
		}
	}
	if len(raw) > 16<<20 {
		return nil, fmt.Errorf("fingerprint bank exceeds 16 MiB")
	}
	b := new(Bank)
	if err = json.Unmarshal(raw, b); err != nil {
		return nil, fmt.Errorf("invalid fingerprint bank JSON")
	}
	n := len(b.Models)
	if n < 2 || n > 256 {
		return nil, fmt.Errorf("invalid fingerprint bank model count")
	}
	seen := map[string]bool{}
	for _, m := range b.Models {
		if m.ID == "" || seen[m.ID] {
			return nil, fmt.Errorf("invalid fingerprint bank model IDs")
		}
		seen[m.ID] = true
	}
	for _, a := range []struct {
		a         artifact
		dimension int
	}{{b.Robust.Hellinger, 355}, {b.Robust.Ordered, 74}} {
		if len(a.a.Mean) != a.dimension || len(a.a.Scale) != a.dimension || len(a.a.Centroids) != n {
			return nil, fmt.Errorf("invalid fingerprint feature dimensions")
		}
		vectors := append(append([][]float64{}, a.a.Basis...), a.a.Centroids...)
		vectors = append(vectors, a.a.Mean, a.a.Scale)
		for _, environment := range a.a.Environments {
			if len(environment) != n {
				return nil, fmt.Errorf("invalid fingerprint environment dimensions")
			}
			vectors = append(vectors, environment...)
		}
		for _, v := range vectors {
			if len(v) != a.dimension {
				return nil, fmt.Errorf("invalid fingerprint vector dimensions")
			}
			for _, x := range v {
				if math.IsNaN(x) || math.IsInf(x, 0) {
					return nil, fmt.Errorf("non-finite fingerprint vector")
				}
			}
		}
		for _, x := range a.a.Scale {
			if x <= 0 {
				return nil, fmt.Errorf("invalid fingerprint feature scale")
			}
		}
	}
	if len(b.Robust.Ordered.Environments) == 0 || b.Robust.Ordered.Weight < 0 || b.Robust.Ordered.Weight > 1 {
		return nil, fmt.Errorf("invalid ordered-block bank")
	}
	for i := 1; i <= 3; i++ {
		beta := b.Calibration[strconv.Itoa(i)].Beta
		if beta <= 0 || math.IsNaN(beta) || math.IsInf(beta, 0) {
			return nil, fmt.Errorf("invalid fingerprint calibration")
		}
	}
	sum := sha256.Sum256(raw)
	b.Version = hex.EncodeToString(sum[:])
	return b, nil
}
func (b *Bank) HasModel(model string) bool {
	for _, m := range b.Models {
		if m.ID == model {
			return true
		}
	}
	return false
}

var digits = regexp.MustCompile(`[0-9]+`)

func ParseNumbers(text string) []int {
	var best, current []int
	end := 0
	for _, loc := range digits.FindAllStringIndex(text, -1) {
		letters := false
		for _, r := range text[end:loc[0]] {
			if unicode.IsLetter(r) {
				letters = true
				break
			}
		}
		if letters && len(current) > 0 {
			if len(current) > len(best) {
				best = current
			}
			current = nil
		}
		value, err := strconv.Atoi(text[loc[0]:loc[1]])
		if err == nil && value >= 1 && value <= 355 {
			current = append(current, value)
		}
		end = loc[1]
	}
	if len(current) > len(best) {
		best = current
	}
	return best
}
func dot(a, b []float64) float64 {
	r := 0.0
	for i, x := range a {
		r += x * b[i]
	}
	return r
}
func normalize(v []float64) []float64 {
	scale := math.Max(math.Sqrt(dot(v, v)), 1e-12)
	for i := range v {
		v[i] /= scale
	}
	return v
}
func standardize(v []float64) []float64 {
	mean := 0.0
	for _, x := range v {
		mean += x
	}
	mean /= float64(len(v))
	variance := 0.0
	for _, x := range v {
		variance += (x - mean) * (x - mean)
	}
	scale := math.Max(math.Sqrt(variance/float64(len(v))), 1e-12)
	for i := range v {
		v[i] = (v[i] - mean) / scale
	}
	return v
}
func project(v []float64, basis [][]float64) []float64 {
	v = append([]float64{}, v...)
	for _, b := range basis {
		p := dot(v, b)
		for i := range v {
			v[i] -= p * b[i]
		}
	}
	return v
}
func featureScale(feature []float64, a artifact) []float64 {
	for i := range feature {
		feature[i] = (feature[i] - a.Mean[i]) / a.Scale[i]
	}
	return feature
}
func scores(v []float64, centroids [][]float64) []float64 {
	out := make([]float64, len(centroids))
	for i, c := range centroids {
		out[i] = dot(v, c)
	}
	return standardize(out)
}
func (b *Bank) score(numbers []int) []float64 {
	marginal := make([]float64, 355)
	for _, n := range numbers {
		marginal[n-1]++
	}
	for i := range marginal {
		marginal[i] = math.Sqrt((marginal[i] + 0.5) / (float64(len(numbers)) + 177.5))
	}
	h := b.Robust.Hellinger
	marginal = scores(normalize(project(featureScale(marginal, h), h.Basis)), h.Centroids)
	o := b.Robust.Ordered
	if o.Weight == 0 {
		return marginal
	}
	ordered := make([]float64, 0, 74)
	start := 0
	for block := 0; block < 4; block++ {
		size := len(numbers) / 4
		if block < len(numbers)%4 {
			size++
		}
		bins := make([]float64, 16)
		for i := range bins {
			bins[i] = 0.5
		}
		for _, n := range numbers[start : start+size] {
			bins[(n-1)*16/355]++
		}
		for i := range bins {
			bins[i] = math.Sqrt(bins[i] / (float64(size) + 8))
		}
		ordered = append(ordered, bins...)
		start += size
	}
	last := make([]float64, 10)
	for i := range last {
		last[i] = 0.5
	}
	for _, n := range numbers {
		last[n%10]++
	}
	for i := range last {
		last[i] = math.Sqrt(last[i] / (float64(len(numbers)) + 5))
	}
	ordered = featureScale(append(ordered, last...), o)
	unit := normalize(append([]float64{}, ordered...))
	template := make([]float64, len(b.Models))
	for i := range template {
		template[i] = math.Inf(-1)
		for _, environment := range o.Environments {
			template[i] = math.Max(template[i], dot(unit, environment[i]))
		}
	}
	standardize(template)
	nuisance := scores(normalize(project(ordered, o.Basis)), o.Centroids)
	for i := range template {
		template[i] = 0.5 * (template[i] + nuisance[i])
	}
	standardize(template)
	for i := range marginal {
		marginal[i] = (1-o.Weight)*marginal[i] + o.Weight*template[i]
	}
	return marginal
}
func (b *Bank) Classify(answers []Answer) Classification {
	result := Classification{BankVersion: b.Version}
	combined := make([]float64, len(b.Models))
	for _, answer := range answers {
		numbers := ParseNumbers(answer.Text)
		result.ParsedNumbers = append(result.ParsedNumbers, len(numbers))
		minimum := int(math.Max(80, math.Ceil(float64(answer.ExpectedCount)*0.55)))
		if len(numbers) < minimum {
			continue
		}
		result.UsedOutputs++
		for i, s := range b.score(numbers) {
			combined[i] += s
		}
	}
	if result.UsedOutputs == 0 {
		return result
	}
	beta := b.Calibration[strconv.Itoa(min(result.UsedOutputs, 3))].Beta
	maximum := math.Inf(-1)
	for i := range combined {
		combined[i] = combined[i] / float64(result.UsedOutputs) * beta
		maximum = math.Max(maximum, combined[i])
	}
	total := 0.0
	for i := range combined {
		combined[i] = math.Exp(combined[i] - maximum)
		total += combined[i]
	}
	for i, m := range b.Models {
		result.Candidates = append(result.Candidates, Candidate{m.ID, combined[i] / total})
	}
	sort.SliceStable(result.Candidates, func(i, j int) bool { return result.Candidates[i].Probability > result.Candidates[j].Probability })
	winner := result.Candidates[0]
	result.Prediction = winner.Model
	result.Probability = &winner.Probability
	return result
}
