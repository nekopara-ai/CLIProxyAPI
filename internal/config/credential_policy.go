package config

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// CredentialPolicy is keyed by auth file name (preferred) or runtime auth ID.
// Nil timezone inherits; an explicitly empty timezone disables rewriting.
type CredentialPolicy struct {
	Timezone    *string           `yaml:"timezone-override,omitempty" json:"timezone_override,omitempty"`
	Country     *string           `yaml:"timezone-override-country,omitempty" json:"timezone_override_country,omitempty"`
	Region      *string           `yaml:"timezone-override-region,omitempty" json:"timezone_override_region,omitempty"`
	City        *string           `yaml:"timezone-override-city,omitempty" json:"timezone_override_city,omitempty"`
	Fingerprint FingerprintPolicy `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
}

// Pointer options distinguish inheritance from explicit false/zero values.
type FingerprintPolicy struct {
	Enabled           *bool             `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Models            []string          `yaml:"models,omitempty" json:"models,omitempty"`
	ExpectedModels    map[string]string `yaml:"expected-models,omitempty" json:"expected-models,omitempty"`
	IntervalSeconds   *int              `yaml:"interval-seconds,omitempty" json:"interval-seconds,omitempty"`
	CooldownSeconds   *int              `yaml:"cooldown-seconds,omitempty" json:"cooldown-seconds,omitempty"`
	RetrySeconds      *int              `yaml:"retry-seconds,omitempty" json:"retry-seconds,omitempty"`
	MaxRetrySeconds   *int              `yaml:"max-retry-seconds,omitempty" json:"max-retry-seconds,omitempty"`
	Confidence        *float64          `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	MinimumAnswers    *int              `yaml:"minimum-answers,omitempty" json:"minimum-answers,omitempty"`
	QuestionRetries   *int              `yaml:"question-retries,omitempty" json:"question-retries,omitempty"`
	DailyRequestLimit *int              `yaml:"daily-request-limit,omitempty" json:"daily-request-limit,omitempty"`
	HistoryLimit      *int              `yaml:"history-limit,omitempty" json:"history-limit,omitempty"`
	RetainAnswers     *bool             `yaml:"retain-answers,omitempty" json:"retain-answers,omitempty"`
}

type FingerprintConfig struct {
	FingerprintPolicy   `yaml:",inline"`
	Workers             int    `yaml:"workers,omitempty" json:"workers,omitempty"`
	StartupDelaySeconds int    `yaml:"startup-delay-seconds,omitempty" json:"startup-delay-seconds,omitempty"`
	JitterSeconds       int    `yaml:"jitter-seconds,omitempty" json:"jitter-seconds,omitempty"`
	StateFile           string `yaml:"state-file,omitempty" json:"state-file,omitempty"`
	BankFile            string `yaml:"bank-file,omitempty" json:"bank-file,omitempty"`
}

func MergeFingerprintPolicy(base, override FingerprintPolicy) FingerprintPolicy {
	if override.Enabled != nil {
		base.Enabled = override.Enabled
	}
	if override.Models != nil {
		base.Models = override.Models
	}
	if override.ExpectedModels != nil {
		base.ExpectedModels = override.ExpectedModels
	}
	if override.IntervalSeconds != nil {
		base.IntervalSeconds = override.IntervalSeconds
	}
	if override.CooldownSeconds != nil {
		base.CooldownSeconds = override.CooldownSeconds
	}
	if override.RetrySeconds != nil {
		base.RetrySeconds = override.RetrySeconds
	}
	if override.MaxRetrySeconds != nil {
		base.MaxRetrySeconds = override.MaxRetrySeconds
	}
	if override.Confidence != nil {
		base.Confidence = override.Confidence
	}
	if override.MinimumAnswers != nil {
		base.MinimumAnswers = override.MinimumAnswers
	}
	if override.QuestionRetries != nil {
		base.QuestionRetries = override.QuestionRetries
	}
	if override.DailyRequestLimit != nil {
		base.DailyRequestLimit = override.DailyRequestLimit
	}
	if override.HistoryLimit != nil {
		base.HistoryLimit = override.HistoryLimit
	}
	if override.RetainAnswers != nil {
		base.RetainAnswers = override.RetainAnswers
	}
	return base
}

func DefaultFingerprintPolicy() FingerprintPolicy {
	yes, no := true, false
	interval, cooldown, retry, maxRetry, minAnswers, retries, daily, history := 3600, 1800, 300, 3600, 3, 1, 300, 10
	confidence := 0.95
	return FingerprintPolicy{Enabled: &yes, Models: []string{"gpt-5.6-sol", "gpt-6-sol", "gpt-6-astra"}, IntervalSeconds: &interval, CooldownSeconds: &cooldown, RetrySeconds: &retry, MaxRetrySeconds: &maxRetry, Confidence: &confidence, MinimumAnswers: &minAnswers, QuestionRetries: &retries, DailyRequestLimit: &daily, HistoryLimit: &history, RetainAnswers: &no}
}

func (p FingerprintPolicy) Validate() error {
	for _, r := range []struct {
		name     string
		v        *int
		min, max int
	}{
		{"interval-seconds", p.IntervalSeconds, 60, 2592000}, {"cooldown-seconds", p.CooldownSeconds, 1, 2592000},
		{"retry-seconds", p.RetrySeconds, 10, 86400}, {"max-retry-seconds", p.MaxRetrySeconds, 10, 2592000},
		{"minimum-answers", p.MinimumAnswers, 1, 3}, {"question-retries", p.QuestionRetries, 0, 2},
		{"daily-request-limit", p.DailyRequestLimit, 3, 100000}, {"history-limit", p.HistoryLimit, 1, 100},
	} {
		if r.v != nil && (*r.v < r.min || *r.v > r.max) {
			return fmt.Errorf("fingerprint.%s must be between %d and %d", r.name, r.min, r.max)
		}
	}
	if p.Confidence != nil && (math.IsNaN(*p.Confidence) || math.IsInf(*p.Confidence, 0) || *p.Confidence < 0.5 || *p.Confidence > 1) {
		return fmt.Errorf("fingerprint.confidence must be between 0.5 and 1")
	}
	if p.Models != nil && len(p.Models) == 0 {
		return fmt.Errorf("fingerprint.models cannot be empty; use enabled: false")
	}
	if len(p.Models) > 32 {
		return fmt.Errorf("fingerprint.models supports at most 32 models")
	}
	seen := map[string]bool{}
	for _, m := range p.Models {
		if strings.TrimSpace(m) == "" || strings.ContainsAny(m, "\r\n\x00") || seen[m] {
			return fmt.Errorf("fingerprint.models must contain distinct nonempty model names")
		}
		seen[m] = true
	}
	for k, v := range p.ExpectedModels {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return fmt.Errorf("fingerprint.expected-models requires nonempty names")
		}
	}
	return nil
}

func (p CredentialPolicy) Validate() error {
	if p.Timezone != nil && strings.TrimSpace(*p.Timezone) != "" {
		if _, err := time.LoadLocation(strings.TrimSpace(*p.Timezone)); err != nil {
			return fmt.Errorf("timezone_override must be a valid IANA timezone, empty, or null")
		}
	}
	return p.Fingerprint.Validate()
}

func (c *Config) ValidateCredentialPolicies() error {
	if c == nil {
		return nil
	}
	if err := c.Fingerprint.FingerprintPolicy.Validate(); err != nil {
		return err
	}
	if c.Fingerprint.Workers < 0 || c.Fingerprint.Workers > 32 {
		return fmt.Errorf("fingerprint.workers must be between 0 and 32")
	}
	if c.Fingerprint.StartupDelaySeconds < 0 || c.Fingerprint.StartupDelaySeconds > 86400 || c.Fingerprint.JitterSeconds < 0 || c.Fingerprint.JitterSeconds > 86400 {
		return fmt.Errorf("fingerprint startup delay and jitter must be between 0 and 86400 seconds")
	}
	for key, p := range c.CredentialPolicies {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("credential-policies requires a nonempty auth file name or ID")
		}
		if err := p.Validate(); err != nil {
			return err
		}
	}
	return nil
}
