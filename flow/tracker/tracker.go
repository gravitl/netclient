package tracker

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/flow/exporter"
	pbflow "github.com/gravitl/netmaker/grpc/flow"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	ct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

type NodeIterator func(func(node *models.CommonNode) bool)

type ParticipantEnricher func(ip string) *pbflow.FlowParticipant

type FlowTracker struct {
	hostID              uuid.UUID
	hostIDStr           string
	nodeIter            NodeIterator
	participantEnricher ParticipantEnricher
	flowExporter        exporter.Exporter
	restoreSysctl       bool
	cancel              context.CancelFunc
	mu                  sync.Mutex
}

func New(nodeIter NodeIterator, participantEnricher ParticipantEnricher, flowExporter exporter.Exporter) (*FlowTracker, error) {
	var hostID uuid.UUID
	nodeIter(func(node *models.CommonNode) bool {
		hostID = node.HostID
		return false
	})

	c := &FlowTracker{
		hostID:              hostID,
		hostIDStr:           hostID.String(),
		nodeIter:            nodeIter,
		participantEnricher: participantEnricher,
		flowExporter:        flowExporter,
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

	var eventType pbflow.EventType
	if event.Type == ct.EventNew {
		eventType = pbflow.EventType_EVENT_START
	} else if event.Type == ct.EventDestroy {
		eventType = pbflow.EventType_EVENT_DESTROY
	} else {
		return nil
	}

	networkID, direction := c.inferNetworkAndDirection(event.Flow)
	if networkID == "" {
		// if flow doesn't belong to any of our networks, ignore it.
		return nil
	}

	flowID := c.getFlowID(event.Flow)
	sentCounter := c.getSentCounter(event.Flow, direction)
	receivedCounter := c.getReceivedCounter(event.Flow, direction)

	flow := *event.Flow
	var icmpType, icmpCode uint8
	if flow.TupleOrig.Proto.Protocol == 1 || flow.TupleOrig.Proto.Protocol == 58 {
		// ICMP
		icmpType = flow.TupleOrig.Proto.ICMPType
		icmpCode = flow.TupleOrig.Proto.ICMPCode
	}

	return c.flowExporter.Export(&pbflow.FlowEvent{
		Type:        eventType,
		FlowId:      flowID,
		NetworkId:   networkID,
		HostId:      c.hostIDStr,
		Protocol:    uint32(flow.TupleOrig.Proto.Protocol),
		SrcPort:     uint32(flow.TupleOrig.Proto.SourcePort),
		DstPort:     uint32(flow.TupleOrig.Proto.DestinationPort),
		IcmpType:    uint32(icmpType),
		IcmpCode:    uint32(icmpCode),
		Direction:   direction,
		Src:         c.participantEnricher(flow.TupleOrig.IP.SourceAddress.String()),
		Dst:         c.participantEnricher(flow.TupleOrig.IP.DestinationAddress.String()),
		StartTsMs:   flow.Timestamp.Start.UnixMilli(),
		EndTsMs:     flow.Timestamp.Stop.UnixMilli(),
		BytesSent:   sentCounter.Bytes,
		BytesRecv:   receivedCounter.Bytes,
		PacketsSent: sentCounter.Packets,
		PacketsRecv: receivedCounter.Packets,
		Status:      uint32(flow.Status),
		Version:     time.Now().UnixMilli(),
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

func (c *FlowTracker) getFlowID(flow *ct.Flow) string {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], flow.ID)
	return uuid.NewSHA1(c.hostID, buf[:]).String()
}

func (c *FlowTracker) inferNetworkAndDirection(flow *ct.Flow) (string, pbflow.Direction) {
	srcIP := net.ParseIP(flow.TupleOrig.IP.SourceAddress.String())
	dstIP := net.ParseIP(flow.TupleOrig.IP.DestinationAddress.String())

	var networkID string
	direction := pbflow.Direction_DIR_UNSPECIFIED
	c.nodeIter(func(node *models.CommonNode) bool {
		if node.Address.IP.Equal(srcIP) || node.Address6.IP.Equal(srcIP) {
			direction = pbflow.Direction_DIR_EGRESS
		} else if node.Address.IP.Equal(dstIP) || node.Address6.IP.Equal(dstIP) {
			direction = pbflow.Direction_DIR_INGRESS
		} else if node.NetworkRange.Contains(srcIP) || node.NetworkRange6.Contains(srcIP) {
			direction = pbflow.Direction_DIR_INGRESS
		} else if node.NetworkRange.Contains(dstIP) || node.NetworkRange6.Contains(dstIP) {
			direction = pbflow.Direction_DIR_EGRESS
		} else {
			return true
		}

		networkID = node.Network
		return false
	})

	return networkID, direction
}

func (c *FlowTracker) getSentCounter(flow *ct.Flow, direction pbflow.Direction) ct.Counter {
	if direction == pbflow.Direction_DIR_INGRESS {
		return flow.CountersReply
	} else if direction == pbflow.Direction_DIR_EGRESS {
		return flow.CountersOrig
	} else {
		return ct.Counter{}
	}
}

func (c *FlowTracker) getReceivedCounter(flow *ct.Flow, direction pbflow.Direction) ct.Counter {
	if direction == pbflow.Direction_DIR_INGRESS {
		return flow.CountersOrig
	} else if direction == pbflow.Direction_DIR_EGRESS {
		return flow.CountersReply
	} else {
		return ct.Counter{}
	}
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
