package fingerprint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type Probe func(context.Context, *coreauth.Auth, string, string) (string, error)
type ModelResult struct {
	Model         string `json:"model"`
	ExpectedModel string `json:"expected_model"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
	Classification
	Answers    []Answer  `json:"answers,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}
type Run struct {
	At      time.Time     `json:"at"`
	Results []ModelResult `json:"results"`
}
type State struct {
	PolicySignature string        `json:"policy_signature,omitempty"`
	Identity        string        `json:"identity"`
	Blocked         bool          `json:"blocked"`
	Running         bool          `json:"running"`
	Reason          string        `json:"reason,omitempty"`
	TriggerModel    string        `json:"trigger_model,omitempty"`
	LastMismatchAt  time.Time     `json:"last_mismatch_at,omitempty"`
	CooldownUntil   time.Time     `json:"cooldown_until,omitempty"`
	NextRunAt       time.Time     `json:"next_run_at"`
	LastRunAt       time.Time     `json:"last_run_at,omitempty"`
	Results         []ModelResult `json:"results,omitempty"`
	History         []Run         `json:"history,omitempty"`
	Error           string        `json:"error,omitempty"`
	Failures        int           `json:"failures"`
	BudgetDay       string        `json:"budget_day"`
	RequestsToday   int           `json:"requests_today"`
}
type Snapshot struct {
	*State
	Enabled            bool                     `json:"enabled"`
	ManuallyDisabled   bool                     `json:"manually_disabled"`
	Effective          config.FingerprintPolicy `json:"effective"`
	ConfigurationError string                   `json:"configuration_error,omitempty"`
}
type Monitor struct {
	mu           sync.Mutex
	cfg          func() *config.Config
	auths        func() []*coreauth.Auth
	probe        Probe
	states       map[string]*State
	active       map[string]bool
	stateFile    string
	storageError string
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	now          func() time.Time
	started      time.Time
}

var current atomic.Pointer[Monitor]

func Current() *Monitor     { return current.Load() }
func SetCurrent(m *Monitor) { current.Store(m) }

// Runtime IDs distinguish multiple logical credentials stored in one source file.
func authKey(a *coreauth.Auth) string {
	if a.ID != "" {
		return a.ID
	}
	return filepath.Base(a.FileName)
}
func filePolicy(cfg *config.Config, a *coreauth.Auth) config.CredentialPolicy {
	p := cfg.CredentialPolicies[a.ID]
	if a.FileName != "" {
		if byName, ok := cfg.CredentialPolicies[filepath.Base(a.FileName)]; ok {
			p = byName
		}
	}
	return p
}

func identity(a *coreauth.Auth) string {
	raw, _ := json.Marshal([]any{a.Provider, a.ID, a.Metadata["account_id"], a.Metadata["email"]})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func policyFor(cfg *config.Config, a *coreauth.Auth) (config.FingerprintPolicy, error) {
	p := config.DefaultFingerprintPolicy()
	if cfg == nil || a == nil {
		return p, fmt.Errorf("configuration unavailable")
	}
	p = config.MergeFingerprintPolicy(p, cfg.Fingerprint.FingerprintPolicy)
	v := filePolicy(cfg, a)
	p = config.MergeFingerprintPolicy(p, v.Fingerprint)
	if raw, ok := a.Metadata["fingerprint"]; ok && raw != nil {
		data, err := json.Marshal(raw)
		if err != nil {
			return p, fmt.Errorf("invalid credential fingerprint policy")
		}
		var override config.FingerprintPolicy
		if err = json.Unmarshal(data, &override); err != nil {
			return p, fmt.Errorf("invalid credential fingerprint policy")
		}
		p = config.MergeFingerprintPolicy(p, override)
	}
	return p, p.Validate()
}
func masterEnabled(cfg *config.Config) bool {
	return cfg != nil && cfg.Fingerprint.Enabled != nil && *cfg.Fingerprint.Enabled
}
func signature(cfg *config.Config, a *coreauth.Auth, p config.FingerprintPolicy) string {
	raw, _ := json.Marshal([]any{identity(a), a.ProxyURL, a.Attributes, cfg.ProxyURL, cfg.TimezoneOverride, filePolicy(cfg, a), a.Metadata["timezone_override"], a.Metadata["headers"], p, cfg.Fingerprint.BankFile, masterEnabled(cfg)})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func New(cfg func() *config.Config, auths func() []*coreauth.Auth, probe Probe) *Monitor {
	m := &Monitor{cfg: cfg, auths: auths, probe: probe, states: map[string]*State{}, active: map[string]bool{}, now: time.Now, started: time.Now()}
	c := cfg()
	if c != nil {
		m.stateFile = c.Fingerprint.StateFile
		if m.stateFile == "" && c.AuthDir != "" {
			m.stateFile = filepath.Join(c.AuthDir, ".fingerprint-state")
		}
	}
	if m.stateFile == "" {
		m.storageError = "fingerprint_state_path_unavailable"
		return m
	}
	raw, err := os.ReadFile(m.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return m
	}
	if err != nil || len(raw) > 32<<20 {
		m.storageError = "fingerprint_state_read_failed"
		return m
	}
	var saved struct {
		Version int               `json:"version"`
		States  map[string]*State `json:"states"`
	}
	if json.Unmarshal(raw, &saved) != nil || saved.Version != 1 || saved.States == nil {
		m.storageError = "fingerprint_state_invalid"
		return m
	}
	for k, s := range saved.States {
		if s == nil || s.Identity == "" {
			m.storageError = "fingerprint_state_invalid"
			return m
		}
		s.Running = false
		m.states[k] = s
	}
	return m
}

// saveLocked is called before each billable probe and each eligibility transition.
func (m *Monitor) saveLocked() error {
	if m.stateFile == "" {
		m.storageError = "fingerprint_state_path_unavailable"
		return errors.New(m.storageError)
	}
	data, err := json.Marshal(struct {
		Version int               `json:"version"`
		States  map[string]*State `json:"states"`
	}{1, m.states})
	if err != nil {
		return err
	}
	dir := filepath.Dir(m.stateFile)
	if err = os.MkdirAll(dir, 0700); err != nil {
		m.storageError = "fingerprint_state_write_failed"
		return err
	}
	f, err := os.CreateTemp(dir, ".fingerprint-state-*")
	if err != nil {
		m.storageError = "fingerprint_state_write_failed"
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, m.stateFile)
	}
	if err == nil {
		d, e := os.Open(dir)
		if e == nil {
			err = d.Sync()
			_ = d.Close()
		} else {
			err = e
		}
	}
	if err != nil {
		m.storageError = "fingerprint_state_write_failed"
	}
	return err
}
func (m *Monitor) Allowed(a *coreauth.Auth, _ string) bool {
	if a == nil || a.Disabled {
		return false
	}
	cfg := m.cfg()
	if !masterEnabled(cfg) {
		return true
	}
	p, err := policyFor(cfg, a)
	if err != nil {
		return false
	}
	if err == nil && p.Enabled != nil && !*p.Enabled {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[authKey(a)]
	if m.storageError != "" {
		return false
	}
	return s == nil || s.Identity != identity(a) || !s.Blocked
}
func (m *Monitor) Snapshot(a *coreauth.Auth) Snapshot {
	cfg := m.cfg()
	p, err := policyFor(cfg, a)
	out := Snapshot{Enabled: masterEnabled(cfg) && p.Enabled != nil && *p.Enabled, ManuallyDisabled: a.Disabled, Effective: p}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.states[authKey(a)]; s != nil && s.Identity == identity(a) {
		raw, _ := json.Marshal(s)
		out.State = &State{}
		_ = json.Unmarshal(raw, out.State)
	}
	if err != nil {
		out.ConfigurationError = err.Error()
	}
	if m.storageError != "" {
		out.ConfigurationError = m.storageError
	}
	return out
}
func (m *Monitor) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.tick(ctx)
			}
		}
	}()
}
func (m *Monitor) Stop() {
	if m == nil {
		return
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	current.CompareAndSwap(m, nil)
}
func (m *Monitor) tick(ctx context.Context) {
	cfg := m.cfg()
	if !masterEnabled(cfg) {
		return
	}
	now := m.now()
	workers := cfg.Fingerprint.Workers
	if workers == 0 {
		workers = 1
	}
	for _, a := range m.auths() {
		if a == nil || a.Disabled {
			continue
		}
		p, err := policyFor(cfg, a)
		if err != nil || p.Enabled == nil || !*p.Enabled || len(p.Models) == 0 {
			continue
		}
		key := authKey(a)
		m.mu.Lock()
		if m.storageError != "" || len(m.active) >= workers {
			m.mu.Unlock()
			return
		}
		if m.active[key] {
			m.mu.Unlock()
			continue
		}
		s := m.states[key]
		if s == nil || s.Identity != identity(a) {
			sum := sha256.Sum256([]byte(key))
			jitter := 0
			if cfg.Fingerprint.JitterSeconds > 0 {
				jitter = int(sum[0]) % cfg.Fingerprint.JitterSeconds
			}
			delay := cfg.Fingerprint.StartupDelaySeconds
			if delay == 0 {
				delay = 30
			}
			s = &State{Identity: identity(a), NextRunAt: m.started.Add(time.Duration(delay+jitter) * time.Second)}
			m.states[key] = s
		}
		stamp := signature(cfg, a, p)
		if s.PolicySignature != stamp {
			if !s.LastRunAt.IsZero() {
				s.NextRunAt = now
			}
			s.PolicySignature = stamp
		}
		if s.Blocked && !s.LastMismatchAt.IsZero() {
			until := s.LastMismatchAt.Add(time.Duration(*p.CooldownSeconds) * time.Second)
			if !s.CooldownUntil.Equal(until) {
				s.CooldownUntil = until
				s.NextRunAt = until
			}
		}
		if s.NextRunAt.After(now) || s.Blocked && s.CooldownUntil.After(now) {
			m.mu.Unlock()
			continue
		}
		s.Running = true
		m.active[key] = true
		m.wg.Add(1)
		m.mu.Unlock()
		go func(a *coreauth.Auth, p config.FingerprintPolicy, stamp string) {
			defer m.wg.Done()
			m.run(ctx, a, p, stamp)
		}(a, p, signature(cfg, a, p))
	}
}
func (m *Monitor) stillCurrent(a *coreauth.Auth, stamp string) bool {
	cfg := m.cfg()
	for _, latest := range m.auths() {
		if latest != nil && authKey(latest) == authKey(a) {
			p, err := policyFor(cfg, latest)
			return err == nil && !latest.Disabled && signature(cfg, latest, p) == stamp
		}
	}
	return false
}
func (m *Monitor) reserve(a *coreauth.Auth, p config.FingerprintPolicy) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[authKey(a)]
	if s == nil || m.storageError != "" {
		return false
	}
	day := m.now().UTC().Format("2006-01-02")
	if s.BudgetDay != day {
		s.BudgetDay = day
		s.RequestsToday = 0
	}
	if s.RequestsToday >= *p.DailyRequestLimit {
		return false
	}
	s.RequestsToday++
	return m.saveLocked() == nil
}
func (m *Monitor) run(ctx context.Context, a *coreauth.Auth, p config.FingerprintPolicy, stamp string) {
	key := authKey(a)
	results := []ModelResult{}
	allMatched := len(p.Models) > 0
	anyMismatch := false
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.active, key)
		if s := m.states[key]; s != nil {
			s.Running = false
		}
		_ = m.saveLocked()
	}()
	// Loading a bank is deliberately outside the state mutex. Runtime bank paths may be reloaded.
	bank, err := LoadBank(m.cfg().Fingerprint.BankFile)
	if err != nil {
		m.finish(a, p, nil, false, false, "reference_bank_unavailable", stamp)
		return
	}
	for _, model := range p.Models {
		if ctx.Err() != nil || !m.stillCurrent(a, stamp) {
			return
		}
		expected := model
		if v := p.ExpectedModels[model]; v != "" {
			expected = v
		}
		r := ModelResult{Model: model, ExpectedModel: expected, StartedAt: m.now(), Status: "error"}
		answers := []Answer{}
		requestError := false
		if !bank.HasModel(expected) {
			r.Error = "model_not_in_reference_bank"
		} else {
			for i, prompt := range Prompts {
				for attempt := 0; attempt <= *p.QuestionRetries; attempt++ {
					if ctx.Err() != nil || !m.stillCurrent(a, stamp) {
						return
					}
					if !m.reserve(a, p) {
						r.Error = "request_budget_or_storage_limit"
						requestError = true
						break
					}
					text, probeErr := m.probe(ctx, a, model, prompt)
					if probeErr != nil {
						r.Error = "upstream_request_failed"
						var status interface{ StatusCode() int }
						if errors.As(probeErr, &status) {
							r.Error = fmt.Sprintf("upstream_http_%d", status.StatusCode())
							if status.StatusCode() == 401 || status.StatusCode() == 403 || status.StatusCode() == 429 {
								requestError = true
								break
							}
						}
						if attempt == *p.QuestionRetries {
							requestError = true
						}
						continue
					}
					if len(text) > 1<<20 {
						r.Error = "answer_too_large"
						requestError = true
						break
					}
					answer := Answer{text, ExpectedCounts[i]}
					one := bank.Classify([]Answer{answer})
					if one.UsedOutputs > 0 {
						answers = append(answers, answer)
						break
					}
					if attempt == *p.QuestionRetries {
						answers = append(answers, answer)
					}
				}
				if requestError {
					break
				}
			}
			r.Classification = bank.Classify(answers)
			if requestError {
				r.Status = "error"
			} else if r.UsedOutputs < *p.MinimumAnswers {
				r.Status = "insufficient"
				r.Error = "insufficient_valid_answers"
			} else if r.Probability == nil || *r.Probability < *p.Confidence {
				r.Status = "inconclusive"
				r.Error = "low_confidence"
			} else if r.Prediction != expected {
				r.Status = "mismatch"
				r.Error = ""
			} else {
				r.Status = "match"
				r.Error = ""
			}
		}
		if *p.RetainAnswers {
			r.Answers = answers
		}
		r.FinishedAt = m.now()
		results = append(results, r)
		if r.Status != "match" {
			allMatched = false
		}
		if r.Status == "mismatch" && m.stillCurrent(a, stamp) {
			// Block all business models immediately, not only after the entire cycle.
			anyMismatch = true
			m.mu.Lock()
			s := m.states[key]
			s.Blocked = true
			s.Reason = "fingerprint_mismatch"
			s.TriggerModel = model
			s.LastMismatchAt = m.now()
			s.CooldownUntil = s.LastMismatchAt.Add(time.Duration(*p.CooldownSeconds) * time.Second)
			s.Results = append([]ModelResult{}, results...)
			_ = m.saveLocked()
			m.mu.Unlock()
		}
		if requestError {
			break
		}
	}
	if len(results) != len(p.Models) {
		allMatched = false
	}
	m.finish(a, p, results, allMatched, anyMismatch, "", stamp)
}
func (m *Monitor) finish(a *coreauth.Auth, p config.FingerprintPolicy, results []ModelResult, allMatched, anyMismatch bool, issue, stamp string) {
	if !m.stillCurrent(a, stamp) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[authKey(a)]
	now := m.now()
	s.LastRunAt = now
	s.Results = results
	s.Error = issue
	s.History = append(s.History, Run{now, results})
	if len(s.History) > *p.HistoryLimit {
		s.History = s.History[len(s.History)-*p.HistoryLimit:]
	}
	if allMatched {
		s.Blocked = false
		s.Reason = ""
		s.TriggerModel = ""
		s.LastMismatchAt = time.Time{}
		s.CooldownUntil = time.Time{}
		s.Failures = 0
		s.NextRunAt = now.Add(time.Duration(*p.IntervalSeconds) * time.Second)
	} else if anyMismatch {
		s.Failures = 0
		s.NextRunAt = s.CooldownUntil
	} else {
		s.Failures++
		retry := *p.RetrySeconds
		for i := 1; i < s.Failures && retry < *p.MaxRetrySeconds; i++ {
			retry = min(retry*2, *p.MaxRetrySeconds)
		}
		s.NextRunAt = now.Add(time.Duration(min(retry, *p.MaxRetrySeconds)) * time.Second)
		if s.Blocked && s.CooldownUntil.After(s.NextRunAt) {
			s.NextRunAt = s.CooldownUntil
		}
	}
	_ = m.saveLocked()
}
