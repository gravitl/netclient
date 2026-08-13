package posture

import (
	"time"

	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
)

// HostPostureStatus mirrors the server's response DTO for
// GET /api/v1/host/{hostid}/posture_status. The server-side definition lives
// in netmaker/models/posture_status.go; the netclient keeps a local mirror so
// it does not need to wait for the netmaker module bump.
type HostPostureStatus struct {
	HostID      string                 `json:"host_id"`
	EvaluatedAt time.Time              `json:"evaluated_at"`
	MDM         *HostMDMStatus         `json:"mdm,omitempty"`
	Networks    []NetworkPostureStatus `json:"networks"`
}

// HostMDMStatus reports the MDM enrollment + compliance verdict the server
// has on file for this host. Netclient renders this; it does not compute it.
type HostMDMStatus struct {
	Provider     string    `json:"provider"`
	MatchedBy    string    `json:"matched_by"`
	Enrolled     bool      `json:"enrolled"`
	Compliant    bool      `json:"compliant"`
	LastSyncedAt time.Time `json:"last_synced_at"`
}

// NetworkPostureStatus holds the per-network posture verdict + any policy
// violations. Severity 0 means "pass".
type NetworkPostureStatus struct {
	NetworkID  string             `json:"network_id"`
	NodeID     string             `json:"node_id"`
	Severity   schema.Severity    `json:"severity"`
	Status     string             `json:"status"`
	Violations []models.Violation `json:"violations"`
}

// Standard status values mirrored from the server.
const (
	StatusPass = "pass"
	StatusWarn = "warn"
	StatusFail = "fail"
)
