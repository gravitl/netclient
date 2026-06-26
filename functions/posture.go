package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/posture"
	"github.com/gravitl/netmaker/schema"
)

// MDMDeniedMessage is the exact string netclient prints when the server
// refuses access because the host is not enrolled or compliant in the
// organization MDM. Wording is part of the user-facing contract.
const MDMDeniedMessage = "Access blocked: this device is not enrolled or compliant in your organization MDM."

// PostureStatus calls GET /api/v1/host/{hostid}/posture_status on the current
// server, renders the result, and returns a suggested process exit code.
//
// Exit codes:
//
//	0 - all networks pass
//	1 - one or more networks have status=fail
//	2 - transport/auth error or MDM denial
//
// On MDM denial (server returns the well-known sentinel error) the standard
// user-facing message is printed to stderr.
func PostureStatus(jsonOutput bool) (int, error) {
	resp, err := posture.FetchStatus("")
	if err != nil {
		err = auth.AsMDMDenied(err)
		if errors.Is(err, auth.ErrMDMDenied) {
			fmt.Fprintln(os.Stderr, MDMDeniedMessage)
			return 2, nil
		}
		return 2, err
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
	} else {
		renderPostureStatus(resp)
	}

	for _, n := range resp.Networks {
		if n.Status == posture.StatusFail {
			return 1, nil
		}
	}
	return 0, nil
}

func renderPostureStatus(r *posture.HostPostureStatus) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	hostID := r.HostID
	if hostID == "" {
		hostID = config.Netclient().ID.String()
	}
	fmt.Fprintf(w, "HOST\t%s\n", hostID)
	if r.MDM != nil {
		ago := "never"
		if !r.MDM.LastSyncedAt.IsZero() {
			ago = humanDuration(time.Since(r.MDM.LastSyncedAt)) + " ago"
		}
		matched := r.MDM.MatchedBy
		if matched == "" {
			matched = "n/a"
		}
		fmt.Fprintf(
			w,
			"MDM\tprovider=%s enrolled=%t compliant=%t (matched by %s, synced %s)\n",
			r.MDM.Provider, r.MDM.Enrolled, r.MDM.Compliant, matched, ago,
		)
	} else {
		fmt.Fprintln(w, "MDM\tnot configured")
	}
	if !r.EvaluatedAt.IsZero() {
		fmt.Fprintf(w, "EVAL\t%s\n", r.EvaluatedAt.Format(time.RFC3339))
	}
	w.Flush()
	fmt.Println()

	if len(r.Networks) == 0 {
		fmt.Println("no networks evaluated")
		return
	}
	for _, n := range r.Networks {
		fmt.Printf("NETWORK  %s\n", n.NetworkID)
		fmt.Printf("  STATUS %s (severity=%s)\n", n.Status, severityLabel(n.Severity))
		if len(n.Violations) == 0 {
			fmt.Println()
			continue
		}
		for _, v := range n.Violations {
			label := v.Attribute
			if v.Name != "" {
				label = v.Name + "[" + v.Attribute + "]"
			}
			fmt.Printf("  - %s  [%s, %s]\n", v.Message, label, severityLabel(v.Severity))
		}
		fmt.Println()
	}
}

func severityLabel(s schema.Severity) string {
	switch s {
	case schema.SeverityUnknown:
		return "unknown"
	case schema.SeverityLow:
		return "low"
	case schema.SeverityMedium:
		return "medium"
	case schema.SeverityHigh:
		return "high"
	case schema.SeverityCritical:
		return "critical"
	}
	return fmt.Sprintf("level-%d", int(s))
}

func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
