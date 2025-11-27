package flow

import (
	"os"
	"testing"
	"time"

	"github.com/gravitl/netclient/flow/exporter"
	"github.com/gravitl/netclient/flow/tracker"
)

func Test_StdoutExporter(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("detected CI environment, skipping test")
	}

	flowExporter := exporter.NewStdoutExporter()
	flowTracker, err := tracker.New(flowExporter)
	if err != nil {
		t.Fatal(err)
	}

	err = flowTracker.TrackConnections()
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Minute)

	err = flowTracker.Close()
	if err != nil {
		t.Fatal(err)
	}
}
