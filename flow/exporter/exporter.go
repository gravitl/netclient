package exporter

import "github.com/gravitl/netmaker/pro/flow/proto"

type Exporter interface {
	Export(event *proto.FlowEvent) error
}
