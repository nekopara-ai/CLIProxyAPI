package helps

import (
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// ConfigForAuth copies only configuration values, never shared credential maps.
// A custom timezone intentionally clears global geography to avoid e.g. Tokyo/US.
func ConfigForAuth(cfg *config.Config, auth *coreauth.Auth) *config.Config {
	if auth == nil {
		return cfg
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	policy, ok := cfg.CredentialPolicies[auth.ID]
	if p, exists := cfg.CredentialPolicies[filepath.Base(auth.FileName)]; exists && auth.FileName != "" {
		policy, ok = p, true
	}
	fields := []struct {
		key    string
		target **string
	}{{"timezone_override", &policy.Timezone}, {"timezone_override_country", &policy.Country}, {"timezone_override_region", &policy.Region}, {"timezone_override_city", &policy.City}}
	for _, f := range fields {
		if value, exists := auth.Attributes[f.key]; exists {
			v := strings.TrimSpace(value)
			*f.target = &v
			ok = true
		}
		if value, exists := auth.Metadata[f.key]; exists && value != nil {
			if s, valid := value.(string); valid {
				v := strings.TrimSpace(s)
				*f.target = &v
				ok = true
			}
		}
	}
	if !ok {
		return cfg
	}
	copy := *cfg
	if policy.Timezone != nil {
		copy.TimezoneOverride = *policy.Timezone
		copy.TimezoneOverrideCountry = ""
		copy.TimezoneOverrideRegion = ""
		copy.TimezoneOverrideCity = ""
	}
	if policy.Country != nil {
		copy.TimezoneOverrideCountry = *policy.Country
	}
	if policy.Region != nil {
		copy.TimezoneOverrideRegion = *policy.Region
	}
	if policy.City != nil {
		copy.TimezoneOverrideCity = *policy.City
	}
	return &copy
}
