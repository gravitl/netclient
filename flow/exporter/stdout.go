package exporter

import (
	"fmt"

	"github.com/gravitl/netmaker/pro/flow/proto"
)

type StdoutExporter struct{}

func NewStdoutExporter() *StdoutExporter {
	return &StdoutExporter{}
}

func (s *StdoutExporter) Export(event *proto.FlowEvent) error {
	fmt.Println(event.String())
	return nil
}
