package exporter

import (
	"fmt"

	pbflow "github.com/gravitl/netmaker/grpc/flow"
)

type StdoutExporter struct{}

func NewStdoutExporter() *StdoutExporter {
	return &StdoutExporter{}
}

func (s *StdoutExporter) Export(event *pbflow.FlowEvent) error {
	fmt.Println(event.String())
	return nil
}
