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
	DaemonStatusOK                  DaemonStatus = "ok"
	DaemonStatusMissingDependencies DaemonStatus = "missing_dependencies"
)

type WireGuardUtil string

const (
	WGQuick             WireGuardUtil = "wg-quick"
	WireGuardExecutable WireGuardUtil = "wireguard.exe"
)

type ErrorResponse struct {
	Message string `json:"message"`
}

type SetServerRequest struct {
	Server string `json:"server"`
}

type GetServerResponse struct {
	Status       Status                `json:"status"`
	Server       string                `json:"server"`
	API          string                `json:"api"`
	APIHost      string                `json:"APIHost"`
	Username     string                `json:"username"`
	AuthToken    string                `json:"auth_token"`
	TenantID     string                `json:"tenant_id"`
	Registered   bool                  `json:"registered"`
	ServerConfig nmConfig.ServerConfig `json:"server_config"`
}

type ConfigureSessionRequest struct {
	Username  string `json:"username"`
	AuthToken string `json:"auth_token"`
	TenantID  string `json:"tenant_id"`
	Password  string `json:"password,omitempty"` // deprecated: ignored; use auth_token (user JWT) only
}

type DaemonHealthStatus struct {
	Status                   DaemonStatus  `json:"status"`
	CurrentVersion           string        `json:"current_version"`
	LatestVersion            string        `json:"latest_version"`
	OS                       string        `json:"os"`
	Arch                     string        `json:"arch"`
	WireGuardUtil            WireGuardUtil `json:"wireguard_util"`
	IsWireGuardUtilInstalled bool          `json:"is_wireguard_util_installed"`
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

// DeviceNetworkView mirrors server device network entries for the desktop UI.
type DeviceNetworkView struct {
	NetworkID           string `json:"network_id"`
	DisplayName         string `json:"display_name,omitempty"`
	Joined              bool   `json:"joined"`
	Connected           bool   `json:"connected"`
	Pending             bool   `json:"pending"`
	Status              string `json:"status"`
	ApprovalRequired    bool   `json:"approval_required"`
	ApprovalRequestedAt *int64 `json:"approval_requested_at,omitempty"`
	JITEnabled          bool   `json:"jit_enabled"`
	JITAppliesToUser    bool   `json:"jit_applies_to_user"`
	HasJITAccess        bool   `json:"has_jit_access"`
	JITPendingRequest   bool   `json:"jit_pending_request"`
	JITExpiresAt        *int64 `json:"jit_expires_at,omitempty"`
}

// DeviceExitNodeView mirrors server device exit-node entries for the desktop UI.
type DeviceExitNodeView struct {
	EgressID        string `json:"egress_id"`
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	Network         string `json:"network"`
	RoutingNodeID   string `json:"routing_node_id,omitempty"`
	RoutingHostName string `json:"routing_host_name,omitempty"`
	Selected        bool   `json:"selected"`
	Status          bool   `json:"status"`
}

// SelectExitNodeRequest selects or clears an exit node for a network.
type SelectExitNodeRequest struct {
	EgressID string `json:"egress_id"`
}
