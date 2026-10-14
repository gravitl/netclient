package functions

import (
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
)

// PreserveConnectionsAfterSync replaces the local node map with the server's
// list, then puts back Connected flags the desktop user still wants.
//
// Peer updates and pulls both do this. Headless has no session, so the
// preserve steps only keep a Connected=true that was already local when the
// server still reports false (the reconnect race). Logout and desired-state
// filtering live in keepLocallyConnected and no-op without a session.
func PreserveConnectionsAfterSync(nodes []models.Node) {
	keepDisconnected := locallyDisconnectedNetworks()
	keepConnected := locallyConnectedNetworks()
	config.SetNodes(nodes)
	keepLocallyDisconnected(keepDisconnected)
	keepLocallyConnected(keepConnected)
	reassertDesiredConnectedFlags()
}

// ReconcileExitIfDesired asks the server to re-select an exit when a desktop
// session still wants one and the server is not advertising it. Headless and
// logged-out sessions return immediately.
func ReconcileExitIfDesired() {
	reconcileDesiredExit()
}

// ApplyStartupConnections restores the desktop user's last connected networks
// before the interface is created. Headless startup has no session and does
// nothing here.
func ApplyStartupConnections() {
	ApplyDesiredConnectedFlags()
}
