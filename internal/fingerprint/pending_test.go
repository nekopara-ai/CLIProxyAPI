package fingerprint

import (
	"testing"
	"time"
)

func TestPendingRetriesWithExistingBackoffWithoutVerdict(t *testing.T) {
	for _, prior := range []string{"", "match", "mismatch"} {
		t.Run(prior, func(t *testing.T) {
			h := setup(t)
			h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
			h.cfg.Fingerprint.MinimumAnswers = ptr(1)
			h.cfg.Fingerprint.RetrySeconds = ptr(60)
			h.cfg.Fingerprint.MaxRetrySeconds = ptr(180)
			good := h.answers["gpt-6-sol"]
			if prior != "" {
				if prior == "mismatch" {
					h.answers["gpt-6-sol"] = h.answers["gpt-5.6-luna"]
				}
				h.cycle()
				h.now = h.m.Snapshot(h.a).ModelStates["gpt-6-sol"].NextRunAt
			}
			h.answers["gpt-6-sol"] = []Answer{good[0], {Text: "invalid", ExpectedCount: good[1].ExpectedCount}, {Text: "invalid", ExpectedCount: good[2].ExpectedCount}}
			for i := 0; i < 4; i++ {
				h.index = map[string]int{}
				h.cycle()
				ms := h.m.Snapshot(h.a).ModelStates["gpt-6-sol"]
				if ms.Result.Status != "pending" || ms.Result.UsedOutputs != 1 || ms.Failures != i+1 || !ms.NextRunAt.Equal(h.now.Add([]time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute, 3 * time.Minute}[i])) || h.m.Allowed(h.a, "gpt-6-sol") != (prior == "match") {
					t.Fatalf("invalid pending state: %+v", ms)
				}
				restarted := New(h.m.cfg, h.m.auths, h.m.probe)
				if restarted.Allowed(h.a, "gpt-6-sol") != (prior == "match") || restarted.Snapshot(h.a).ModelStates["gpt-6-sol"].Failures != i+1 || !restarted.Snapshot(h.a).ModelStates["gpt-6-sol"].NextRunAt.Equal(ms.NextRunAt) {
					t.Fatal("restart changed eligibility")
				}
				calls := h.calls
				h.now = ms.NextRunAt.Add(-time.Second)
				h.cycle()
				if h.calls != calls {
					t.Fatal("retried early")
				}
				h.now = ms.NextRunAt
			}
			h.answers["gpt-6-sol"] = good
			h.index = map[string]int{}
			h.cycle()
			if !h.m.Allowed(h.a, "gpt-6-sol") || h.m.Snapshot(h.a).Results[0].Status != "match" || h.m.Snapshot(h.a).ModelStates["gpt-6-sol"].Failures != 0 {
				t.Fatal("complete result did not recover")
			}
		})
	}
}
