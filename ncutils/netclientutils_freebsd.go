package ncutils

import (
	"context"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/exp/slog"
)

// RunCmdFormatted - run a command formatted for freebsd
func RunCmdFormatted(command string, printerr bool) (string, error) {
	debug.PrintStack()

	args := strings.Fields(command)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Start()
	cmd.Wait()
	out, err := cmd.CombinedOutput()
	if err != nil && printerr {
		slog.Warn("error running command: ", "command", command, "output", strings.TrimSuffix(string(out), "\n"), "error", err.Error())
	}
	return string(out), err
}

// GetEmbedded - if files required for freebsd, put here
func GetEmbedded() error {
	return nil
}

// Runs Commands for FreeBSD
func RunCmd(command string, printerr bool) (string, error) {
	args := strings.Fields(command)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	//cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	//go func() {
	//<-ctx.Done()
	//_ = syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
	//}()
	if err := cmd.Run(); err != nil {
		slog.Warn("error running command with CmdRun: ", "command", command, "error", err)
	}

	out, err := cmd.CombinedOutput()
	if err != nil && printerr {
		slog.Warn("error running command: ", "command", command, "output", strings.TrimSuffix(string(out), "\n"), "error", err.Error())
	}
	return string(out), err
}

// IsBridgeNetwork - check if the interface is a bridge type
func IsBridgeNetwork(ifaceName string) bool {
	return false
}
