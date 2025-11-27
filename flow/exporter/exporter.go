package exporter

import nmmodels "github.com/gravitl/netmaker/models"

type Exporter interface {
	Export(event nmmodels.FlowEvent) error
}
