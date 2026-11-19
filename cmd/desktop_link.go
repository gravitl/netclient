//go:build desktop

package cmd

import (
	// Desktop registers functions.GUI hooks (desired state, uiapi, demote-on-removal).
	// Default builds are headless (hooks nil). Pass -tags desktop for the GUI daemon.
	_ "github.com/gravitl/netclient/desktop"
)
