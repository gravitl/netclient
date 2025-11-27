package tracker

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netclient/flow/exporter"
	"github.com/gravitl/netmaker/logger"
	nmmodels "github.com/gravitl/netmaker/models"
	ct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

type FlowTracker struct {
	flowExporter  exporter.Exporter
	restoreSysctl bool
	cancel        context.CancelFunc
	mu            sync.Mutex
}

func New(flowExporter exporter.Exporter) (*FlowTracker, error) {
	c := &FlowTracker{
		flowExporter: flowExporter,
	}

	var err error
	err = c.enableAccounting()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *FlowTracker) TrackConnections() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}

	conn, err := ct.Dial(nil)
	if err != nil {
		return err
	}

	events := make(chan ct.Event, 200)
	errChan, err := conn.Listen(events, 1, []netfilter.NetlinkGroup{
		netfilter.GroupCTNew,
		netfilter.GroupCTUpdate,
		netfilter.GroupCTDestroy,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel

	go c.startEventHandler(ctx, conn, events, errChan)

	return nil
}

func (c *FlowTracker) startEventHandler(ctx context.Context, conn *ct.Conn, events chan ct.Event, errChan chan error) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-events:
			err := c.handleEvent(e)
			if err != nil {
				logger.Log(0, fmt.Sprintf("Error handling event: %v", err))
			}
		case err := <-errChan:
			logger.Log(0, fmt.Sprintf("Error occurred while listening to ct events: %v", err))
			err = conn.Close()
			if err != nil {
				logger.Log(0, fmt.Sprintf("Error closing ct connection: %v", err))
			}
		}
	}

}

func (c *FlowTracker) handleEvent(event ct.Event) error {
	if event.Flow == nil {
		return nil
	}

	var eventType nmmodels.FlowEventType
	if event.Type == ct.EventNew {
		eventType = nmmodels.FlowStart
	} else if event.Type == ct.EventUpdate {
		eventType = nmmodels.FlowUpdate
	} else if event.Type == ct.EventDestroy {
		eventType = nmmodels.FlowDestroy
	} else {
		return nil
	}

	flow := *event.Flow

	var enrichedProtocol *nmmodels.EnrichedProtocol
	if flow.TupleOrig.Proto.Protocol == 1 || flow.TupleOrig.Proto.Protocol == 58 {
		// ICMP
		enrichedProtocol = &nmmodels.EnrichedProtocol{
			ICMPType: flow.TupleOrig.Proto.ICMPType,
			ICMPCode: flow.TupleOrig.Proto.ICMPCode,
		}
	} else if flow.TupleOrig.Proto.Protocol == 6 && flow.ProtoInfo.TCP != nil {
		// TCP
		enrichedProtocol = &nmmodels.EnrichedProtocol{
			TCPState:               flow.ProtoInfo.TCP.State,
			TCPOriginalWindowScale: flow.ProtoInfo.TCP.OriginalWindowScale,
			TCPReplyWindowScale:    flow.ProtoInfo.TCP.ReplyWindowScale,
			TCPOriginalFlags:       flow.ProtoInfo.TCP.OriginalFlags,
			TCPReplyFlags:          flow.ProtoInfo.TCP.ReplyFlags,
		}
	}

	return c.flowExporter.Export(nmmodels.FlowEvent{
		ID:       flow.ID,
		Type:     eventType,
		Status:   flow.Status,
		Protocol: flow.TupleOrig.Proto.Protocol,
		OriginPeer: nmmodels.Peer{
			IP:   flow.TupleOrig.IP.SourceAddress.String(),
			Port: flow.TupleOrig.Proto.SourcePort,
		},
		ReplyPeer: nmmodels.Peer{
			IP:   flow.TupleOrig.IP.DestinationAddress.String(),
			Port: flow.TupleOrig.Proto.DestinationPort,
		},
		OriginCounter: nmmodels.Counter{
			Packets: flow.CountersOrig.Packets,
			Bytes:   flow.CountersOrig.Bytes,
		},
		ReplyCounter: nmmodels.Counter{
			Packets: flow.CountersReply.Packets,
			Bytes:   flow.CountersReply.Bytes,
		},
		Timestamp:        time.Now(),
		Start:            flow.Timestamp.Start,
		Stop:             flow.Timestamp.Stop,
		EnrichedProtocol: enrichedProtocol,
	})
}

func (c *FlowTracker) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cancel()
	c.cancel = nil

	return c.disableAccounting()
}

func (c *FlowTracker) enableAccounting() error {
	modified, err := c.setConnTrackAccountingValue(1)
	if err != nil {
		return err
	}

	c.restoreSysctl = modified
	return nil
}

func (c *FlowTracker) disableAccounting() error {
	if c.restoreSysctl {
		_, err := c.setConnTrackAccountingValue(0)
		if err != nil {
			return err
		}

		c.restoreSysctl = false
	}

	return nil
}

func (c *FlowTracker) setConnTrackAccountingValue(value int) (bool, error) {
	const path = "/proc/sys/net/netfilter/nf_conntrack_acct"

	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	currValue, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false, err
	}

	if currValue == value {
		return false, nil
	}

	err = os.WriteFile(path, []byte(strconv.Itoa(value)), 0644)
	if err != nil {
		return false, err
	}

	return true, nil
}
