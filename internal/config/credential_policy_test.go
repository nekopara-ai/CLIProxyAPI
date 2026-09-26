package config

import (
	"gopkg.in/yaml.v3"
	"testing"
)

func TestCredentialPolicyConfiguration(t *testing.T) {
	var c Config
	err := yaml.Unmarshal([]byte("fingerprint:\n  enabled: false\n  models: [gpt-6-sol]\n  cooldown-seconds: 120\ncredential-policies:\n  a.json:\n    timezone-override: ''\n    fingerprint:\n      interval-seconds: 300\n"), &c)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.ValidateCredentialPolicies(); err != nil {
		t.Fatal(err)
	}
	if c.CredentialPolicies["a.json"].Timezone == nil || *c.CredentialPolicies["a.json"].Timezone != "" {
		t.Fatal("off lost")
	}
	if c.Fingerprint.Enabled == nil || *c.Fingerprint.Enabled {
		t.Fatal("off lost")
	}
}
func TestCredentialPolicyRejectInvalid(t *testing.T) {
	for _, raw := range []string{"fingerprint: {models: []}", "fingerprint: {confidence: 0}", "fingerprint: {interval-seconds: 0}", "credential-policies: {a: {timezone-override: Mars/Test}}"} {
		var c Config
		if err := yaml.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatal(err)
		}
		if c.ValidateCredentialPolicies() == nil {
			t.Fatal(raw)
		}
	}
}
