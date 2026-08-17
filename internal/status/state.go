// Package status computes deterministic synchronization states from exact
// content digests rather than timestamps.
package status

type State string

const (
	Synchronized      State = "synchronized"
	PlaintextChanged  State = "plaintext_changed"
	IncomingConsent   State = "incoming_ciphertext_requiring_consent"
	Conflict          State = "conflict"
	MissingPlaintext  State = "missing_plaintext"
	MissingCiphertext State = "missing_ciphertext"
	MissingFiles      State = "missing_files"
	Uninitialized     State = "uninitialized"
	FirstRunCompare   State = "first_run_compare_required"
)

type Input struct {
	HasBaseline      bool
	PlaintextExists  bool
	CiphertextExists bool
	PlaintextDigest  string
	CiphertextDigest string
	BaselinePlain    string
	BaselineCipher   string
}

func Calculate(input Input) State {
	if !input.HasBaseline {
		switch {
		case input.PlaintextExists && input.CiphertextExists:
			return FirstRunCompare
		case input.PlaintextExists:
			return MissingCiphertext
		case input.CiphertextExists:
			return MissingPlaintext
		default:
			return MissingFiles
		}
	}
	if !input.PlaintextExists && !input.CiphertextExists {
		return MissingFiles
	}
	if !input.PlaintextExists {
		return MissingPlaintext
	}
	if !input.CiphertextExists {
		return MissingCiphertext
	}
	plainChanged := input.PlaintextDigest != input.BaselinePlain
	cipherChanged := input.CiphertextDigest != input.BaselineCipher
	switch {
	case !plainChanged && !cipherChanged:
		return Synchronized
	case plainChanged && !cipherChanged:
		return PlaintextChanged
	case !plainChanged && cipherChanged:
		return IncomingConsent
	default:
		return Conflict
	}
}
