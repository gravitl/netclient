package functions

import "github.com/gravitl/netclient/uiapi"

func init() {
	uiapi.SetHandlers(uiapi.HandlerDeps{
		RegisterSession: RegisterSession,
		ReleaseSession:  ReleaseSession,
		Connect:         Connect,
		Disconnect:      Disconnect,
		IsRegistered:    IsRegisteredToServer,
	})
}
