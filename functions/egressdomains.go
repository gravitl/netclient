package functions

import (
	"context"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/dns"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

const egressDomainCheckInterval = 5 * time.Minute

// syncEgressDomains updates local egress-domain state and triggers a resolution pass.
func syncEgressDomains(domains []models.EgressDomain) {
	if len(domains) == 0 {
		wireguard.SetEgressDomains(nil)
		dns.ClearEgressDomainPatterns()
		return
	}
	wireguard.SetEgressDomains(domains)
	dns.SyncEgressDomainPatterns(domains)
	go CheckEgressDomainUpdates()
}

// StartEgressDomainMonitor periodically re-resolves egress domains on the egress gateway node.
func StartEgressDomainMonitor(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(egressDomainCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if len(wireguard.GetEgressDomains()) == 0 {
					continue
				}
				slog.Debug("periodic egress domain check")
				CheckEgressDomainUpdates()
			}
		}
	}()
}

func isLocalEgressGateway(domainI models.EgressDomain) bool {
	hostID := config.Netclient().Host.ID
	if hostID.String() == "" {
		return true
	}
	if domainI.Host.ID.String() == "" {
		return true
	}
	return domainI.Host.ID == hostID
}
