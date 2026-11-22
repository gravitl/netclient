package cmd

import (
	"context"
	"fmt"
	"io"
	stdslog "log/slog"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/schema"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

// startupVerbosityLevels is the mapping setupLogging applies, 1 is Error and 3 is Info
var startupVerbosityLevels = map[int]slog.Level{
	0: slog.LevelError,
	1: slog.LevelError,
	2: slog.LevelWarn,
	3: slog.LevelInfo,
	4: slog.LevelDebug,
}

// runtimeVerbosityLevels is the mapping a runtime verbosity change applies, 1 is Info and 3 is Debug
var runtimeVerbosityLevels = map[int]slog.Level{
	0: slog.LevelError,
	1: slog.LevelInfo,
	2: slog.LevelWarn,
	3: slog.LevelDebug,
	4: slog.LevelDebug,
}

// resetVerbosity sets the disk verbosity and the -v flag, installs the startup loggers and the standard library default
func resetVerbosity(flag, disk int) {
	config.Netclient().Verbosity = disk
	logger.Verbosity = 0
	flags := viper.New()
	flags.Set("verbosity", flag)
	setupLogging(flags)
	stdslog.SetDefault(stdslog.New(stdslog.NewTextHandler(io.Discard, nil)))
}

// checkLevels asserts both loggers enable exactly the levels at or above std and exp
func checkLevels(t *testing.T, cell string, std, exp slog.Level) {
	ctx := context.Background()
	for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		gotExp := slog.Default().Enabled(ctx, level)
		gotStd := stdslog.Default().Enabled(ctx, stdslog.Level(level))
		if gotExp != (level >= exp) || gotStd != (stdslog.Level(level) >= stdslog.Level(std)) {
			t.Errorf("%s: %s enabled exp/log-slog = %v/%v, want %v/%v", cell, level, gotExp, gotStd, level >= exp, stdslog.Level(level) >= stdslog.Level(std))
		}
	}
}

func TestSetVerbosityAppliesToStartupLogger(t *testing.T) {
	t.Cleanup(func() { resetVerbosity(0, 0) })
	for flag := 0; flag <= 4; flag++ {
		for disk := 0; disk <= 4; disk++ {
			cell := fmt.Sprintf("-v %d, disk verbosity %d,", flag, disk)
			resetVerbosity(flag, disk)
			checkLevels(t, cell+" startup", slog.LevelInfo, min(startupVerbosityLevels[flag], startupVerbosityLevels[disk]))
			// the config is written back and read again once the goroutines start, the -v floor holds the level there
			config.UpdateNetclient(config.Config{Host: schema.Host{Verbosity: disk}})
			reread := min(runtimeVerbosityLevels[flag], runtimeVerbosityLevels[disk])
			checkLevels(t, cell+" re-read", reread, reread)
			if lv, cv := logger.Verbosity, config.Netclient().Verbosity; lv != disk || cv != disk {
				t.Errorf("%s logger %d config %d, want %d and %d", cell, lv, cv, disk, disk)
			}
		}
	}
}

func TestSetVerbosityKeepsStartupFlag(t *testing.T) {
	ctx := context.Background()
	resetVerbosity(4, 0)
	// the daemon writes the config and reads it back once its goroutines start
	config.UpdateNetclient(config.Config{Host: schema.Host{Verbosity: 0}})
	if !slog.Default().Enabled(ctx, slog.LevelDebug) || !stdslog.Default().Enabled(ctx, stdslog.LevelDebug) {
		t.Errorf("verbosity 4 given at startup, reloaded to 0: DEBUG enabled = false, want true")
	}
	if level, verbosity := logger.Verbosity, config.Netclient().Verbosity; level != 0 || verbosity != 0 {
		t.Errorf("verbosity 4 given at startup, reloaded to 0: logger verbosity %d, config verbosity %d, want 0 and 0", level, verbosity)
	}
}
