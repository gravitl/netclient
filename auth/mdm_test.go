package auth

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/gravitl/netclient/ncutils"
)

func TestAsMDMDeniedNil(t *testing.T) {
	if got := AsMDMDenied(nil); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestAsMDMDeniedUnrelatedError(t *testing.T) {
	in := errors.New("boom")
	if got := AsMDMDenied(in); got != in {
		t.Errorf("expected unchanged error, got %v", got)
	}
}

func TestAsMDMDeniedNon403(t *testing.T) {
	in := ncutils.ErrStatusNotOk{Status: http.StatusUnauthorized, Message: "mdm_posture_denied"}
	got := AsMDMDenied(in)
	if errors.Is(got, ErrMDMDenied) {
		t.Errorf("non-403 should not be classified as MDM denial; got %v", got)
	}
}

func TestAsMDMDenied403WithoutMarker(t *testing.T) {
	in := ncutils.ErrStatusNotOk{Status: http.StatusForbidden, Message: "forbidden"}
	got := AsMDMDenied(in)
	if errors.Is(got, ErrMDMDenied) {
		t.Errorf("403 without marker should pass through; got %v", got)
	}
}

func TestAsMDMDenied403WithMarker(t *testing.T) {
	in := ncutils.ErrStatusNotOk{Status: http.StatusForbidden, Message: "mdm_posture_denied"}
	got := AsMDMDenied(in)
	if !errors.Is(got, ErrMDMDenied) {
		t.Fatalf("expected ErrMDMDenied, got %v", got)
	}
}

func TestAsMDMDeniedThroughWrap(t *testing.T) {
	wrapped := fmt.Errorf("send: %w", ncutils.ErrStatusNotOk{
		Status:  http.StatusForbidden,
		Message: "MDM_POSTURE refused",
	})
	got := AsMDMDenied(wrapped)
	if !errors.Is(got, ErrMDMDenied) {
		t.Fatalf("expected ErrMDMDenied through wrap, got %v", got)
	}
}
