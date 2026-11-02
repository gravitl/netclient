package uiapi

import nmConfig "github.com/gravitl/netmaker/config"

type Status string

const (
	Idle      Status = "idle"
	Loading   Status = "loading"
	Restoring Status = "restoring"
	Running   Status = "running"
	Closing   Status = "closing"
)

type DaemonStatus string

const (
	DaemonStatusOK DaemonStatus = "ok"
)

type ErrorResponse struct {
	Message string `json:"message"`
	// Code is a stable machine-readable reason for the GUI (e.g. server_incompatible).
	Code string `json:"code,omitempty"`
}

type SetServerRequest struct {
	Server string `json:"server"`
}

type GetServerResponse struct {
	Status             Status                `json:"status"`
	Server             string                `json:"server"`
	API                string                `json:"api"`
	APIHost            string                `json:"APIHost"`
	Username           string                `json:"username"`
	AuthToken          string                `json:"auth_token"`
	TenantID           string                `json:"tenant_id"`
	Registered         bool                  `json:"registered"`
	ServerConfig       nmConfig.ServerConfig `json:"server_config"`
	RestorePhase       string                `json:"restore_phase,omitempty"`
	WantIGW            bool                  `json:"want_igw,omitempty"`
	AutoExit           bool                  `json:"auto_exit,omitempty"`
	DesiredEgressID    string                `json:"desired_egress_id,omitempty"`
	DesiredExitNetwork string                `json:"desired_exit_network,omitempty"`
	// Notice is a one-shot message for the GUI, such as a manual exit that
	// failed its post-connect VPN health check.
	Notice *SessionNotice `json:"notice,omitempty"`
}

// SessionNotice is a message the desktop GUI can show from GET /session.
type SessionNotice struct {
	Code    string `json:"code"`
	Network string `json:"network,omitempty"`
	Message string `json:"message"`
}

type ConfigureSessionRequest struct {
	Username  string `json:"username"`
	AuthToken string `json:"auth_token"`
	TenantID  string `json:"tenant_id"`
	Password  string `json:"password,omitempty"` // deprecated: ignored; use auth_token (user JWT) only
}

type DaemonHealthStatus struct {
	Status         DaemonStatus `json:"status"`
	CurrentVersion string       `json:"current_version"`
	LatestVersion  string       `json:"latest_version"`
	OS             string       `json:"os"`
	Arch           string       `json:"arch"`
}

type InterfaceStatus string

const (
	InterfaceStatusUp   InterfaceStatus = "up"
	InterfaceStatusDown InterfaceStatus = "down"
)

type Peer struct {
	PublicKey           string   `json:"public_key"`
	AllowedIPs          []string `json:"allowed_ips"`
	Endpoint            string   `json:"endpoint"`
	PersistentKeepalive string   `json:"persistent_keepalive"`
	LastHandshakeTime   string   `json:"last_handshake_time"`
	ReceiveBytes        int64    `json:"receive_bytes"`
	SendBytes           int64    `json:"send_bytes"`
}

type Connection struct {
	Status   InterfaceStatus `json:"status"`
	Address  *string         `json:"address,omitempty"`
	MTU      *int            `json:"mtu,omitempty"`
	Peer     *Peer           `json:"peer,omitempty"`
	Gateways []any           `json:"gateways,omitempty"`
}
