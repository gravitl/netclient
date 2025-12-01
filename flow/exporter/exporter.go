package exporter

import pbflow "github.com/gravitl/netmaker/grpc/flow"

type Exporter interface {
	Export(event *pbflow.FlowEvent) error
}
