package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/uiapi"
	"github.com/spf13/cobra"
)

// refuseIfDesktopSession blocks CLI commands that change the device while
// Netmaker Desktop is logged in. Headless installs have no session, so the
// CLI stays usable there. Read-only commands do not use this hook.
func refuseIfDesktopSession(cmd *cobra.Command, _ []string) error {
	uiapi.EnsureSessionLoaded()
	if !uiapi.IsSessionActive() {
		return nil
	}
	cmd.SilenceUsage = true
	return fmt.Errorf("this device is managed by Netmaker Desktop; use the app instead of %q", cmd.CommandPath())
}
