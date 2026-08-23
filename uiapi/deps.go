package uiapi

import (
	"errors"
)

type HandlerDeps struct {
	RegisterSession     func(server, username, authToken, password, tenantID string) error
	ReleaseSession      func(clearServer bool) error
	Connect             func(network string) error
	Disconnect          func(network string) error
	IsRegistered        func(server string) bool
	FetchNetworks       func(server, token string) ([]DeviceNetworkView, error)
	JoinNetwork         func(network, server, token string) (joinStatus string, err error)
	LeaveNetwork        func(network, server, token string) error
	CancelJoin          func(network, server, token string) error
	RequestJIT          func(network, server, token, reason string) error
	Sync                func(token string) error
	ListExitNodes       func(network, server, token string) ([]DeviceExitNodeView, error)
	GetSelectedExitNode func(network, server, token string) (*DeviceExitNodeView, error)
	SelectExitNode      func(network, server, token, egressID string) (*DeviceExitNodeView, error)
}

var deps HandlerDeps

// SetHandlers wires netclient operations into the desktop API layer.
func SetHandlers(d HandlerDeps) {
	deps = d
}

func registerSession(server, username, authToken, password, tenantID string) error {
	if deps.RegisterSession == nil {
		return errHandlersNotConfigured
	}
	return deps.RegisterSession(server, username, authToken, password, tenantID)
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

func fetchNetworks(server, token string) ([]DeviceNetworkView, error) {
	if deps.FetchNetworks == nil {
		return nil, errHandlersNotConfigured
	}
	return deps.FetchNetworks(server, token)
}

func joinNetwork(network, server, token string) (string, error) {
	if deps.JoinNetwork == nil {
		return "", errHandlersNotConfigured
	}
	return deps.JoinNetwork(network, server, token)
}

func leaveNetwork(network, server, token string) error {
	if deps.LeaveNetwork == nil {
		return errHandlersNotConfigured
	}
	return deps.LeaveNetwork(network, server, token)
}

func cancelJoin(network, server, token string) error {
	if deps.CancelJoin == nil {
		return errHandlersNotConfigured
	}
	return deps.CancelJoin(network, server, token)
}

func requestJIT(network, server, token, reason string) error {
	if deps.RequestJIT == nil {
		return errHandlersNotConfigured
	}
	return deps.RequestJIT(network, server, token, reason)
}

func syncDevice(token string) error {
	if deps.Sync == nil {
		return errHandlersNotConfigured
	}
	return deps.Sync(token)
}

func listExitNodes(network, server, token string) ([]DeviceExitNodeView, error) {
	if deps.ListExitNodes == nil {
		return nil, errHandlersNotConfigured
	}
	return deps.ListExitNodes(network, server, token)
}

func getSelectedExitNode(network, server, token string) (*DeviceExitNodeView, error) {
	if deps.GetSelectedExitNode == nil {
		return nil, errHandlersNotConfigured
	}
	return deps.GetSelectedExitNode(network, server, token)
}

func selectExitNode(network, server, token, egressID string) (*DeviceExitNodeView, error) {
	if deps.SelectExitNode == nil {
		return nil, errHandlersNotConfigured
	}
	return deps.SelectExitNode(network, server, token, egressID)
}

func isRegistered(server string) bool {
	if deps.IsRegistered == nil {
		return isRegisteredToServer()
	}
	return deps.IsRegistered(server)
}

var errHandlersNotConfigured = errors.New("desktop API handlers not configured")
