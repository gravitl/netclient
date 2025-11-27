package exporter

import (
	"fmt"

	nmmodels "github.com/gravitl/netmaker/models"
)

type StdoutExporter struct{}

func NewStdoutExporter() *StdoutExporter {
	return &StdoutExporter{}
}

func (s *StdoutExporter) Export(event nmmodels.FlowEvent) error {
	fmt.Println(event.String())
	return nil
}
