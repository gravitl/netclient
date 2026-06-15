package uiapi

import "errors"

type HandlerDeps struct {
	RegisterSession func(server, username, authToken, password string) error
	ReleaseSession  func(clearServer bool) error
	Connect         func(network string) error
	Disconnect      func(network string) error
	IsRegistered    func(server string) bool
}

var deps HandlerDeps

// SetHandlers wires netclient operations into the desktop API layer.
func SetHandlers(d HandlerDeps) {
	deps = d
}

func registerSession(server, username, authToken, password string) error {
	if deps.RegisterSession == nil {
		return errHandlersNotConfigured
	}
	return deps.RegisterSession(server, username, authToken, password)
}

func releaseSessionFn(clearServer bool) error {
	if deps.ReleaseSession == nil {
		return errHandlersNotConfigured
	}
	return deps.ReleaseSession(clearServer)
}

func connectNetwork(network string) error {
	if deps.Connect == nil {
		return errHandlersNotConfigured
	}
	return deps.Connect(network)
}

func disconnectNetwork(network string) error {
	if deps.Disconnect == nil {
		return errHandlersNotConfigured
	}
	return deps.Disconnect(network)
}

func isRegistered(server string) bool {
	if deps.IsRegistered == nil {
		return isRegisteredToServer()
	}
	return deps.IsRegistered(server)
}

var errHandlersNotConfigured = errors.New("desktop API handlers not configured")
