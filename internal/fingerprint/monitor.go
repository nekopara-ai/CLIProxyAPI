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
	Deferred      *coreauth.DiagnosticUnavailable `json:"deferred,omitempty"`
	Model         string                          `json:"model"`
	ExpectedModel string                          `json:"expected_model"`
	Status        string                          `json:"status"`
	Error         string                          `json:"error,omitempty"`
	Confidence    float64                         `json:"confidence,omitempty"`
	Classification
	Answers    []Answer  `json:"answers,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}
type Run struct {
	At      time.Time                 `json:"at"`
	Results []ModelResult             `json:"results"`
	Policy  *config.FingerprintPolicy `json:"policy,omitempty"`
}
type Progress struct {
	StartedAt          time.Time `json:"started_at"`
	Model              string    `json:"model"`
	Question           int       `json:"question"`
	Attempt            int       `json:"attempt"`
	CompletedQuestions int       `json:"completed_questions"`
	TotalQuestions     int       `json:"total_questions"`
	RequestStartedAt   time.Time `json:"request_started_at"`
	LastEventAt        time.Time `json:"last_event_at,omitempty"`
	ReceivedBytes      int64     `json:"received_bytes"`
}
type State struct {
	ModelStates     map[string]*ModelState    `json:"model_states,omitempty"`
	PolicySignature string                    `json:"policy_signature,omitempty"`
	ResultSignature string                    `json:"result_signature,omitempty"`
	ResultPolicy    *config.FingerprintPolicy `json:"result_policy,omitempty"`
	Progress        *Progress                 `json:"progress,omitempty"`
	CurrentResults  []ModelResult             `json:"current_results,omitempty"`
	Identity        string                    `json:"identity"`
	Blocked         bool                      `json:"blocked"`
	Running         bool                      `json:"running"`
	Reason          string                    `json:"reason,omitempty"`
	TriggerModel    string                    `json:"trigger_model,omitempty"`
	LastMismatchAt  time.Time                 `json:"last_mismatch_at,omitempty"`
	CooldownUntil   time.Time                 `json:"cooldown_until,omitempty"`
	NextRunAt       time.Time                 `json:"next_run_at"`
	LastRunAt       time.Time                 `json:"last_run_at,omitempty"`
	Results         []ModelResult             `json:"results,omitempty"`
	History         []Run                     `json:"history,omitempty"`
	Error           string                    `json:"error,omitempty"`
	Failures        int                       `json:"failures"`
	BudgetDay       string                    `json:"budget_day"`
	RequestsToday   int                       `json:"requests_today"`
}
type Snapshot struct {
	*State
	Enabled            bool                     `json:"enabled"`
	Supported          bool                     `json:"supported"`
	ResultsStale       bool                     `json:"results_stale"`
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
	active       map[string]*activeRun
	stateFile    string
	storageError string
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	now          func() time.Time
	started      time.Time
}

type activeRun struct {
	signature string
	cancel    context.CancelFunc
}

func supported(a *coreauth.Auth) bool { return a != nil && a.Provider == "codex" }

func copyPolicy(p config.FingerprintPolicy) *config.FingerprintPolicy {
	raw, _ := json.Marshal(p)
	var out config.FingerprintPolicy
	_ = json.Unmarshal(raw, &out)
	return &out
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
	m := &Monitor{cfg: cfg, auths: auths, probe: probe, states: map[string]*State{}, active: map[string]*activeRun{}, now: time.Now, started: time.Now()}
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
		s.Progress = nil
		s.CurrentResults = nil
		migrateModelStates(s)
		for model, ms := range s.ModelStates {
			if model == "" || ms == nil || ms.Result != nil && ms.Result.Model != model {
				m.storageError = "fingerprint_state_invalid"
				return m
			}
		}
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
func (m *Monitor) Allowed(a *coreauth.Auth, model string) bool {
	if a == nil || a.Disabled {
		return false
	}
	if !supported(a) {
		return true
	}
	cfg := m.cfg()
	if !masterEnabled(cfg) {
		return true
	}
	p, err := policyFor(cfg, a)
	if p.Enabled != nil && !*p.Enabled {
		return true
	}
	model = configuredModel(p, model)
	if model == "" {
		return true
	}
	if err != nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[authKey(a)]
	if m.storageError != "" {
		return false
	}
	if s == nil || s.Identity != identity(a) {
		return true
	}
	// Multiple configured reasoning variants still represent the same model.
	// A passing variant must not bypass a sibling variant's active exclusion.
	for _, candidate := range p.Models {
		if ms := s.ModelStates[candidate]; modelKey(candidate) == modelKey(model) && ms != nil && ms.Blocked {
			return false
		}
	}
	return true
}
func (m *Monitor) Snapshot(a *coreauth.Auth) Snapshot {
	cfg := m.cfg()
	p, err := policyFor(cfg, a)
	out := Snapshot{Supported: supported(a), Enabled: supported(a) && masterEnabled(cfg) && p.Enabled != nil && *p.Enabled, ManuallyDisabled: a.Disabled, Effective: p}
	if !out.Supported {
		return out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.states[authKey(a)]; s != nil && s.Identity == identity(a) {
		raw, _ := json.Marshal(s)
		out.State = &State{}
		_ = json.Unmarshal(raw, out.State)
		refreshSummary(out.State, p)
		configured := make(map[string]bool, len(p.Models))
		for _, model := range p.Models {
			configured[model] = true
		}
		for model, ms := range out.ModelStates {
			if !configured[model] {
				delete(out.ModelStates, model)
				continue
			}
			ms.ResultsStale = ms.Result != nil && (ms.ResultSignature == "" || ms.ResultSignature != signature(cfg, a, p))
			out.ResultsStale = out.ResultsStale || ms.ResultsStale
		}
		if out.Running {
			out.NextRunAt = time.Time{}
		}
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
	auths := m.auths()
	// Reconcile active work even while disabled or every worker is occupied.
	// This cancels obsolete requests without introducing network timeouts.
	valid := make(map[string]string)
	for _, a := range auths {
		if !supported(a) || a.Disabled || !masterEnabled(cfg) {
			continue
		}
		if p, err := policyFor(cfg, a); err == nil && p.Enabled != nil && *p.Enabled {
			valid[authKey(a)] = signature(cfg, a, p)
		}
	}
	m.mu.Lock()
	for key, run := range m.active {
		if valid[key] != run.signature {
			run.cancel()
		}
	}
	m.mu.Unlock()
	if !masterEnabled(cfg) {
		return
	}
	now := m.now()
	workers := cfg.Fingerprint.Workers
	if workers == 0 {
		workers = 1
	}
	for _, a := range auths {
		if !supported(a) || a.Disabled {
			continue
		}
		p, err := policyFor(cfg, a)
		if err != nil || p.Enabled == nil || !*p.Enabled || len(p.Models) == 0 {
			continue
		}
		key := authKey(a)
		m.mu.Lock()
		if m.storageError != "" {
			m.mu.Unlock()
			return
		}
		if m.active[key] != nil {
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
		models := syncModels(s, p, stamp, now)
		models = m.filterAvailable(s, a, p, models, now)
		if len(models) == 0 {
			m.mu.Unlock()
			continue
		}
		if len(m.active) >= workers {
			m.mu.Unlock()
			continue
		}
		s.Running = true
		s.NextRunAt = time.Time{}
		s.Progress = &Progress{StartedAt: now, TotalQuestions: len(models) * len(Prompts)}
		s.CurrentResults = nil
		runCtx, cancel := context.WithCancel(ctx)
		m.active[key] = &activeRun{signature: stamp, cancel: cancel}
		m.wg.Add(1)
		m.mu.Unlock()
		go func(a *coreauth.Auth, p config.FingerprintPolicy, stamp string) {
			defer m.wg.Done()
			defer cancel()
			m.run(runCtx, a, p, stamp, models)
		}(a, p, stamp)
	}
}
func (m *Monitor) stillCurrent(a *coreauth.Auth, stamp string) bool {
	return m.currentAuth(a, stamp) != nil
}
func (m *Monitor) currentAuth(a *coreauth.Auth, stamp string) *coreauth.Auth {
	cfg := m.cfg()
	for _, latest := range m.auths() {
		if latest != nil && authKey(latest) == authKey(a) {
			p, err := policyFor(cfg, latest)
			if err == nil && !latest.Disabled && signature(cfg, latest, p) == stamp {
				return latest
			}
			return nil
		}
	}
	return nil
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
func (m *Monitor) run(ctx context.Context, a *coreauth.Auth, p config.FingerprintPolicy, stamp string, models []string) {
	key := authKey(a)
	results := []ModelResult{}
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.active, key)
		if s := m.states[key]; s != nil {
			s.Running = false
			s.Progress = nil
			s.CurrentResults = nil
			refreshSummary(s, p)
		}
		_ = m.saveLocked()
	}()
	ctx = context.WithValue(ctx, activityKey{}, func(bytes int) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if s := m.states[key]; s != nil && s.Progress != nil {
			s.Progress.LastEventAt = m.now()
			s.Progress.ReceivedBytes += int64(bytes)
		}
	})
	// Loading a bank is deliberately outside the state mutex. Runtime bank paths may be reloaded.
	bank, err := LoadBank(m.cfg().Fingerprint.BankFile)
	if err != nil {
		m.finish(a, p, nil, models, "reference_bank_unavailable", stamp)
		return
	}
	for _, model := range models {
		if ctx.Err() != nil || !m.stillCurrent(a, stamp) {
			return
		}
		m.mu.Lock()
		wait := m.states[key].ModelStates[model].Wait
		waiting := wait != nil && wait.RetryAt.After(m.now())
		m.mu.Unlock()
		if waiting {
			continue
		}
		expected := model
		if v := p.ExpectedModels[model]; v != "" {
			expected = v
		}
		r := ModelResult{Model: model, ExpectedModel: expected, StartedAt: m.now(), Status: "error", Confidence: *p.Confidence}
		answers := []Answer{}
		requestError := false
		if !bank.HasModel(expected) {
			r.Error = "model_not_in_reference_bank"
		} else {
			for i, prompt := range Prompts {
				for attempt := 0; attempt <= *p.QuestionRetries; attempt++ {
					latest := m.currentAuth(a, stamp)
					if ctx.Err() != nil || latest == nil {
						return
					}
					if wait := coreauth.DiagnosticAvailability(latest, model, m.now()); wait != nil {
						r.Deferred = wait
						m.deferProbe(a, model, p, wait)
						requestError = true
						break
					}
					m.mu.Lock()
					progress := m.states[key].Progress
					progress.Model, progress.Question, progress.Attempt = model, i+1, attempt+1
					progress.RequestStartedAt = m.now()
					progress.LastEventAt = time.Time{}
					progress.ReceivedBytes = 0
					m.mu.Unlock()
					if !m.reserve(a, p) {
						r.Error = "request_budget_or_storage_limit"
						requestError = true
						break
					}
					text, probeErr := m.probe(ctx, latest, model, prompt)
					var local *coreauth.DiagnosticUnavailable
					if errors.As(probeErr, &local) {
						m.refundReservation(a)
					}
					if ctx.Err() != nil || !m.stillCurrent(a, stamp) {
						return
					}
					if probeErr != nil {
						if wait := deferredError(probeErr, m.now()); wait != nil {
							if !wait.RetryAt.After(m.now()) {
								wait.RetryAt = m.now().Add(retryDelay(p, 1))
							}
							// The manager may have learned a longer cooldown concurrently.
							if current := m.currentAuth(a, stamp); current != nil {
								if known := coreauth.DiagnosticAvailability(current, model, m.now()); known != nil && known.RetryAt.After(wait.RetryAt) {
									wait.RetryAt = known.RetryAt
								}
							}
							r.Deferred = wait
							m.deferProbe(a, model, p, wait)
							requestError = true
							break
						}
						r.Error = "upstream_request_failed"
						var status interface{ StatusCode() int }
						if errors.As(probeErr, &status) {
							r.Error = fmt.Sprintf("upstream_http_%d", status.StatusCode())
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
				m.mu.Lock()
				m.states[key].Progress.CompletedQuestions++
				m.mu.Unlock()
			}
			r.Classification = bank.Classify(answers)
			if r.Deferred != nil {
				r.Status, r.Error = "deferred", ""
				r.Prediction, r.Probability = "", nil
			} else if requestError {
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
		if !m.stillCurrent(a, stamp) {
			return
		}
		m.mu.Lock()
		m.states[key].CurrentResults = append([]ModelResult{}, results...)
		applyModelResult(m.states[key], p, r, stamp, m.now())
		_ = m.saveLocked()
		m.mu.Unlock()
		if requestError && r.Deferred == nil {
			break
		}
	}
	m.finish(a, p, results, models, "", stamp)
}
func (m *Monitor) finish(a *coreauth.Auth, p config.FingerprintPolicy, results []ModelResult, models []string, issue, stamp string) {
	if !m.stillCurrent(a, stamp) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[authKey(a)]
	now := m.now()
	if len(results) == 0 && issue == "" {
		refreshSummary(s, p)
		_ = m.saveLocked()
		return
	}
	s.LastRunAt = now
	s.ResultSignature = stamp
	s.ResultPolicy = copyPolicy(p)
	s.Error = issue
	s.History = append(s.History, Run{At: now, Results: results, Policy: copyPolicy(p)})
	if len(s.History) > *p.HistoryLimit {
		s.History = s.History[len(s.History)-*p.HistoryLimit:]
	}
	completed := make(map[string]bool)
	for _, r := range results {
		completed[r.Model] = true
	}
	// An account-level request failure must not immediately hammer the next model.
	// Defer unattempted models without fabricating a result or changing eligibility.
	for _, model := range models {
		if !completed[model] {
			ms := s.ModelStates[model]
			if ms.Wait != nil && ms.Wait.RetryAt.After(now) {
				continue
			}
			ms.NextRunAt = now.Add(retryDelay(p, ms.Failures+1))
			if ms.Blocked && ms.CooldownUntil.After(ms.NextRunAt) {
				ms.NextRunAt = ms.CooldownUntil
			}
		}
	}
	refreshSummary(s, p)
	_ = m.saveLocked()
}
