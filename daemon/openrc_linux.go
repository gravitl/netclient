package daemon

import (
	"errors"

	"golang.org/x/exp/slog"
)

// setupOpenRC - sets up openrc daemon
func setupOpenRC() error {
	slog.Info("OpenRC not supported")
	return errors.New("OpenRC not supported")
}

func startOpenRC() error {
	slog.Info("OpenRC not supported")
	return errors.New("OpenRC not supported")
}

func stopOpenRC() error {
	slog.Info("OpenRC not supported")
	return errors.New("OpenRC not supported")
}

func removeOpenRC() error {
	slog.Info("OpenRC not supported")
	return errors.New("OpenRC not supported")
}
