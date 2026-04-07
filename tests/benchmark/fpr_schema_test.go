// Package benchmark_test exercises FalsePositiveRate JSON serialization.
package benchmark_test

import (
	"encoding/json"
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// TestFalsePositiveRateJSONRoundTrip verifies that FalsePositiveRate marshals
// fpr_measured correctly and that the field survives an unmarshal round-trip.
func TestFalsePositiveRateJSONRoundTrip(t *testing.T) {
	t.Run("fpr_measured false", func(t *testing.T) {
		fpr := model.FalsePositiveRate{
			FP:          0,
			TN:          0,
			TNTimeouts:  0,
			FPR:         model.MetricFloat(0),
			FPRLow:      model.MetricFloat(0),
			FPRHigh:     model.MetricFloat(0),
			FPRMeasured: false,
		}

		data, err := json.Marshal(fpr)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}

		// fpr_measured must appear in the JSON output.
		raw := string(data)
		if !containsSubstring(raw, `"fpr_measured":false`) {
			t.Errorf("expected fpr_measured:false in JSON, got: %s", raw)
		}

		var got model.FalsePositiveRate
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if got.FPRMeasured != false {
			t.Errorf("FPRMeasured: got %v want false", got.FPRMeasured)
		}
	})

	t.Run("fpr_measured true", func(t *testing.T) {
		fpr := model.FalsePositiveRate{
			FP:          1,
			TN:          9,
			TNTimeouts:  0,
			FPR:         model.MetricFloat(0.1),
			FPRLow:      model.MetricFloat(0.0),
			FPRHigh:     model.MetricFloat(0.4),
			FPRMeasured: true,
		}

		data, err := json.Marshal(fpr)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}

		// fpr_measured must appear in the JSON output.
		raw := string(data)
		if !containsSubstring(raw, `"fpr_measured":true`) {
			t.Errorf("expected fpr_measured:true in JSON, got: %s", raw)
		}

		var got model.FalsePositiveRate
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if got.FPRMeasured != true {
			t.Errorf("FPRMeasured: got %v want true", got.FPRMeasured)
		}
		if got.FP != 1 {
			t.Errorf("FP: got %d want 1", got.FP)
		}
		if got.TN != 9 {
			t.Errorf("TN: got %d want 9", got.TN)
		}
	})
}

// containsSubstring reports whether s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && func() bool {
		for i := 0; i <= len(s)-len(substr); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	}()
}
