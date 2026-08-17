package app

import (
	"context"
	"strings"
	"testing"
)

func TestBroadConflictAndRecoveryFlagsAreRejectedBeforeMutation(t *testing.T) {
	w := &Workspace{}
	tests := []struct {
		name string
		run  func() error
		want string
	}{
		{"encrypt force all", func() error {
			_, err := w.Encrypt(context.Background(), "", true, EncryptOptions{Force: true})
			return err
		}, "one exact file"},
		{"decrypt force all", func() error {
			_, err := w.Decrypt(context.Background(), "", true, DecryptOptions{Force: true})
			return err
		}, "one exact file"},
		{"decrypt incoming all", func() error {
			_, err := w.Decrypt(context.Background(), "", true, DecryptOptions{AcceptIncoming: strings.Repeat("0", 64)})
			return err
		}, "one exact configured file"},
		{"decrypt recovery all", func() error {
			_, err := w.Decrypt(context.Background(), "", true, DecryptOptions{RecoverNoManifest: true})
			return err
		}, "one exact configured file"},
		{"sync incoming without path", func() error {
			_, _, err := w.Sync(context.Background(), "", SyncOptions{AcceptIncoming: strings.Repeat("0", 64)})
			return err
		}, "one exact configured file"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestIncomingDigestMustBeCanonicalSHA256(t *testing.T) {
	w := &Workspace{}
	_, err := w.Decrypt(context.Background(), "secret", false, DecryptOptions{AcceptIncoming: "ABC"})
	if err == nil || !strings.Contains(err.Error(), "64 lowercase hexadecimal") {
		t.Fatalf("invalid digest error = %v", err)
	}
}

func TestProjectSnapshotTokensAreRequiredBeforeMutation(t *testing.T) {
	w := &Workspace{}
	tests := []struct {
		name string
		run  func() error
		want string
	}{
		{"decrypt", func() error {
			_, err := w.Decrypt(context.Background(), "secret", false, DecryptOptions{})
			return err
		}, "exact canonical snapshot"},
		{"sync", func() error {
			_, _, err := w.Sync(context.Background(), "secret", SyncOptions{})
			return err
		}, "exact canonical project snapshot"},
		{"unprotect", func() error {
			return w.Unprotect(context.Background(), "secret", UnprotectOptions{AcceptMappingChanges: true})
		}, "exact canonical snapshot"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want text %q", err, test.want)
			}
		})
	}
}
