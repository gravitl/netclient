package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gravitl/netclient/ncutils"
)

// ErrMDMDenied is returned (via wrapping) when the netmaker server refuses a
// request because the host is not enrolled or compliant in the configured
// MDM. Callers should detect it with errors.Is and surface MDMDeniedMessage
// to the operator instead of a generic transport error.
var ErrMDMDenied = errors.New("device not enrolled or compliant in MDM")

// mdmDenialMarker is the case-insensitive substring the netmaker server
// includes in its error message when refusing on MDM grounds. The exact
// shape is owned by the server side; the substring is stable enough to use
// as a marker without depending on a specific phrasing.
const mdmDenialMarker = "mdm_posture"

// AsMDMDenied returns a wrapped ErrMDMDenied when err carries the well-known
// MDM denial signature (HTTP 403 + message containing "mdm_posture"), and
// otherwise returns err unchanged. The original ErrStatusNotOk remains in
// the wrap chain so existing transport handling still works.
func AsMDMDenied(err error) error {
	if err == nil {
		return nil
	}
	var notOk ncutils.ErrStatusNotOk
	if !errors.As(err, &notOk) {
		return err
	}
	if notOk.Status != http.StatusForbidden {
		return err
	}
	if !strings.Contains(strings.ToLower(notOk.Message), mdmDenialMarker) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrMDMDenied, err)
}
