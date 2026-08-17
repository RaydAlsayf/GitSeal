package status

import "testing"

func TestFourBaselineStates(t *testing.T) {
	base := Input{HasBaseline: true, PlaintextExists: true, CiphertextExists: true, PlaintextDigest: "p", CiphertextDigest: "c", BaselinePlain: "p", BaselineCipher: "c"}
	tests := []struct {
		plain, cipher string
		want          State
	}{
		{"p", "c", Synchronized},
		{"p2", "c", PlaintextChanged},
		{"p", "c2", IncomingConsent},
		{"p2", "c2", Conflict},
	}
	for _, tt := range tests {
		input := base
		input.PlaintextDigest, input.CiphertextDigest = tt.plain, tt.cipher
		if got := Calculate(input); got != tt.want {
			t.Errorf("Calculate(%q,%q) = %q, want %q", tt.plain, tt.cipher, got, tt.want)
		}
	}
}
