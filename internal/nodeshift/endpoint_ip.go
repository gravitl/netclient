package nodeshift

import (
	"errors"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netmaker/logger"
)

var errPollerTimeout = errors.New("poller timeout")

func EndpointIPPoller(retry, timeout time.Duration) func() error {
	if retry == 0 {
		return func() error { return nil }
	}
	if timeout == 0 {
		timeout = 120 * time.Second
	}

	return func() error {
		ticker := time.NewTicker(retry)
		defer ticker.Stop()

		timeoutC := time.After(timeout)

		for range ticker.C {
			select {
			case <-timeoutC:
				return errPollerTimeout
			default:
				if len(config.Netclient().EndpointIP) != 0 {
					return nil
				}

				if err := daemon.Restart(); err != nil {
					logger.Log(3, "daemon restart failed:", err.Error())
				}
			}

		}

		return nil
	}
}
