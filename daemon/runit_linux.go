package daemon

import (
	"errors"

	"golang.org/x/exp/slog"
)

// setuprunit - sets up runit daemon
func setuprunit() error {
	slog.Info("runit not supported")
	return errors.New("runit not supported")
}

// startrunit - starts runit daemon
func startrunit() error {
	slog.Info("runit not supported")
	return errors.New("runit not supported")
}

// stoprunit - stops runit daemon
func stoprunit() error {
	slog.Info("runit not supported")
	return errors.New("runit not supported")
}

// restartrunit - restarts runit daemon
func restartrunit() error {
	slog.Info("runit not supported")
	return errors.New("runit not supported")
}

// removerunit - removes runit daemon
func removerunit() error {
	slog.Info("runit not supported")
	return errors.New("runit not supported")
}
