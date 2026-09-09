package posture

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
)

// fakeRunner serves canned responses keyed by command or file path.
type fakeRunner struct {
	cmds  map[string]string
	files map[string]string
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if v, ok := f.cmds[key]; ok {
		return v, nil
	}
	return "", errors.New("not found: " + key)
}

func (f fakeRunner) ReadFile(path string) (string, error) {
	if v, ok := f.files[path]; ok {
		return v, nil
	}
	return "", os.ErrNotExist
}

// TestCollectCrossPlatform validates the fields Collect() guarantees on every
// supported GOOS: hostname + os. Platform-specific fields are exercised by
// the per-OS extractor tests below.
func TestCollectCrossPlatform(t *testing.T) {
	id := Collect()
	if id.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", id.OS, runtime.GOOS)
	}
	if id.Hostname == "" {
		t.Error("Hostname should not be empty")
	}
}

// withRunner swaps in a fake runner for the duration of a test.
func withRunner(t *testing.T, r runner) {
	t.Helper()
	prev := defaultRunner
	defaultRunner = r
	t.Cleanup(func() { defaultRunner = prev })
}

func TestCollectUsesInjectedRunner(t *testing.T) {
	// We can't fully exercise platform output cross-platform; this just
	// confirms the runner indirection is wired (Collect() does not panic
	// when probes fail).
	withRunner(t, fakeRunner{})
	id := Collect()
	if id.OS != runtime.GOOS {
		t.Fatalf("OS = %q", id.OS)
	}
}
