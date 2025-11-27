package flow

import (
	"os"
	"testing"
	"time"

	"github.com/gravitl/netclient/flow/conntrack"
	"github.com/gravitl/netclient/flow/exporter"
)

func Test_StdoutExporter(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("detected CI environment, skipping test")
	}

	flowExporter := exporter.NewStdoutExporter()
	connTracker, err := conntrack.New(flowExporter)
	if err != nil {
		t.Fatal(err)
	}

	err = connTracker.TrackConnections()
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Minute)

	err = connTracker.Close()
	if err != nil {
		t.Fatal(err)
	}
}
