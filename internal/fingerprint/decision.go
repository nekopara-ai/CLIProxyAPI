package fingerprint

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func decisionMode(p config.FingerprintPolicy) string {
	if p.DecisionMode == nil {
		return config.FingerprintDecisionExact
	}
	mode := strings.ToLower(strings.TrimSpace(*p.DecisionMode))
	if mode == "" {
		return config.FingerprintDecisionExact
	}
	return mode
}

func isLunaPrediction(model string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(model)), "luna")
}

func acceptsPrediction(p config.FingerprintPolicy, expected, prediction string) (bool, string) {
	if strings.TrimSpace(prediction) == "" {
		return false, "fingerprint_unverified"
	}
	if decisionMode(p) == config.FingerprintDecisionRejectLuna {
		if isLunaPrediction(prediction) {
			return false, "luna_model_detected"
		}
		return true, ""
	}
	return prediction == expected, ""
}
