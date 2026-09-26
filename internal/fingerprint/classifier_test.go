package fingerprint

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type parityCase struct {
	Prediction  string   `json:"prediction"`
	Probability float64  `json:"probability"`
	Answers     []Answer `json:"answers"`
}

func parityCases(t *testing.T) []parityCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []parityCase
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}
func TestClassifierReferenceParity(t *testing.T) {
	b, err := LoadBank("")
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range parityCases(t) {
		r := b.Classify(c.Answers)
		if r.Prediction != c.Prediction || r.Probability == nil || math.Abs(*r.Probability-c.Probability) > 1e-10 || r.UsedOutputs != 3 {
			t.Fatalf("case %d: %+v want %s %.14f", i, r, c.Prediction, c.Probability)
		}
	}
}
func TestClassifierMissingIsNotZero(t *testing.T) {
	b, _ := LoadBank("")
	r := b.Classify([]Answer{{"No answer", 300}, {"1,2,3", 310}})
	if r.Probability != nil || r.Prediction != "" || r.UsedOutputs != 0 {
		t.Fatalf("%+v", r)
	}
}
func TestParserLongestRunAndThreshold(t *testing.T) {
	ns := ParseNumbers("300 numbers: 1,355,0,356,5 中文 7 8")
	if len(ns) != 3 || ns[1] != 355 {
		t.Fatal(ns)
	}
	b, _ := LoadBank("")
	for count, used := range map[int]int{164: 0, 165: 1} {
		r := b.Classify([]Answer{{strings.Repeat("87,", count), 300}})
		if r.UsedOutputs != used {
			t.Fatal(count, r.UsedOutputs)
		}
	}
}
func TestRejectMalformedBank(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bank.json")
	_ = os.WriteFile(p, []byte(`{"models":[{"id":"x"},{"id":"y"}]}`), 0600)
	if _, err := LoadBank(p); err == nil {
		t.Fatal("accepted invalid dimensions")
	}
}
