package fingerprint

import (
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestRejectLunaKeepsFullClassification(t *testing.T) {
	bank, err := LoadBank("")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range parityCases(t) {
		t.Run(c.Prediction, func(t *testing.T) {
			h := setup(t)
			h.cfg.Fingerprint.DecisionMode = ptr(config.FingerprintDecisionRejectLuna)
			h.cfg.Fingerprint.Models = []string{"gpt-6.1-sol"}
			h.answers["gpt-6.1-sol"] = c.Answers
			want := bank.Classify(c.Answers)
			h.cycle()
			s := h.m.Snapshot(h.a)
			got := s.Results[0]
			if h.calls != 3 || !reflect.DeepEqual(got.Classification, want) {
				t.Fatalf("classification changed: calls=%d got=%+v want=%+v", h.calls, got.Classification, want)
			}
			blocked := isLunaPrediction(c.Prediction)
			if s.Blocked != blocked || h.m.Allowed(h.a, "gpt-6.1-sol(high)") == blocked {
				t.Fatalf("wrong eligibility: %+v", s)
			}
			again := New(h.m.cfg, h.m.auths, h.m.probe)
			if again.Allowed(h.a, "gpt-6.1-sol") == blocked {
				t.Fatal("restart changed verdict")
			}
		})
	}
}

func TestDecisionModes(t *testing.T) {
	for _, prediction := range []string{"gpt-5.6-luna", "gpt-6-luna", "GPT-6.1-LUNA", "gpt-6-astra", "gpt-6-sol", "claude-opus-5", ""} {
		p := config.DefaultFingerprintPolicy()
		got, _ := acceptsPrediction(p, "gpt-6.1-sol", prediction)
		if got != (prediction != "" && !isLunaPrediction(prediction)) {
			t.Fatal(prediction, got)
		}
		p.DecisionMode = ptr(config.FingerprintDecisionExact)
		got, _ = acceptsPrediction(p, "gpt-6-astra", prediction)
		if got != (prediction == "gpt-6-astra") {
			t.Fatal("exact", prediction, got)
		}
	}
}

func TestRejectLunaStillRequiresConfidenceAndCompleteAnswers(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		h := setup(t)
		h.cfg.Fingerprint.DecisionMode = ptr(config.FingerprintDecisionRejectLuna)
		h.cfg.Fingerprint.Models = []string{"gpt-6.1-sol"}
		h.answers["gpt-6.1-sol"] = append([]Answer{}, h.answers["gpt-6-sol"]...)
		want := "inconclusive"
		if incomplete {
			h.answers["gpt-6.1-sol"][1].Text = ""
			want = "pending"
		} else {
			h.cfg.Fingerprint.Confidence = ptr(1.0)
		}
		h.cycle()
		s := h.m.Snapshot(h.a)
		if s.Results[0].Status != want || h.m.Allowed(h.a, "gpt-6.1-sol") {
			t.Fatalf("%+v", s)
		}
	}
}
