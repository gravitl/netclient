package packet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netmaker/logger"
)

var (
	snapshotLen int32         = 65048
	promiscuous bool          = true
	timeout     time.Duration = 1 * time.Microsecond
)

func getOutboundHandler(ifaceName string) (*pcap.Handle, error) {

	// Open device
	handle, err := pcap.OpenLive(ifaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		logger.Log(1, "failed to get outbound router for iface: ", ifaceName, err.Error())
		return nil, err
	}

	return handle, nil
}

func getInboundHandler(ifaceName string) (*pcap.Handle, error) {

	// Open device
	handle, err := pcap.OpenLive(ifaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		logger.Log(1, "failed to get outbound router for iface: ", ifaceName, err.Error())
		return nil, err
	}
	return handle, nil
}

func startInBoundRouter(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	inBoundHandler := config.GetCfg().RouterCfg.InboundHandler
	packetSource := gopacket.NewPacketSource(inBoundHandler, config.GetCfg().RouterCfg.InboundHandler.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		default:
			packet, err := packetSource.NextPacket()
			if err == nil {
				//printPktInfo(packet, true)
				pktBytes, shouldRoute := routePkt(packet, true)
				if !shouldRoute {
					continue
				}
				if err := inBoundHandler.WritePacketData(pktBytes); err != nil {
					logger.Log(0, "failed to inject pkt by inbound handler: ", err.Error())
				}
			}
		}

	}
}

func startOutBoundRouter(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	outBoundHandler := config.GetCfg().RouterCfg.OutBoundHandler
	packetSource := gopacket.NewPacketSource(outBoundHandler, config.GetCfg().RouterCfg.OutBoundHandler.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		default:
			packet, err := packetSource.NextPacket()
			if err == nil {
				//printPktInfo(packet, false)
				pktBytes, shouldRoute := routePkt(packet, false)
				if !shouldRoute {
					continue
				}
				if err := outBoundHandler.WritePacketData(pktBytes); err != nil {
					logger.Log(0, "failed to inject pkt by outbound handler: ", err.Error())
				}

			}
		}

	}
}

// StartRouter - sniffs the the interface
func StartRouter() error {
	var err error
	defer func() {
		config.GetCfg().ResetRouter()
		if err != nil {
			logger.Log(0, "---------> Failed to start router: ", err.Error())
		}
		logger.Log(0, "-----> Stopping Router...")
	}()
	if config.GetCfg().IsIfaceNil() {
		return errors.New("iface is nil")
	}
	ifaceName := config.GetCfg().GetIface().Name
	logger.Log(1, "Starting Packet router for iface: ", ifaceName)
	outHandler, err := getOutboundHandler(ifaceName)
	if err != nil {
		return err
	}
	inHandler, err := getInboundHandler(ifaceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	config.GetCfg().SetRouterHandlers(inHandler, outHandler, cancel)
	err = config.GetCfg().SetBPFFilter()
	if err != nil {
		return err
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go startInBoundRouter(ctx, wg)
	wg.Add(1)
	go startOutBoundRouter(ctx, wg)
	wg.Wait()
	return nil
}

func printPktInfo(packet gopacket.Packet, inbound bool) {

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.  ", inbound)
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()

	}
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

func routePkt(pkt gopacket.Packet, inbound bool) ([]byte, bool) {
	if pkt.NetworkLayer() != nil {
		flow := pkt.NetworkLayer().NetworkFlow()
		src, dst := flow.Endpoints()
		var srcIP, dstIP net.IP
		if inbound {
			if rInfo, found := config.GetCfg().GetRoutingInfo(src.String(), inbound); found {
				srcIP = rInfo.InternalIP
				dstIP = net.ParseIP(dst.String())
			}
		} else {
			if rInfo, found := config.GetCfg().GetRoutingInfo(dst.String(), inbound); found {
				srcIP = net.ParseIP(src.String())
				dstIP = rInfo.ExternalIP
			}
		}
		if srcIP != nil && dstIP != nil {
			if pkt.NetworkLayer().(*layers.IPv4) != nil {
				pkt.NetworkLayer().(*layers.IPv4).SrcIP = srcIP
				pkt.NetworkLayer().(*layers.IPv4).DstIP = dstIP
			} else if pkt.NetworkLayer().(*layers.IPv6) != nil {
				pkt.NetworkLayer().(*layers.IPv6).SrcIP = srcIP
				pkt.NetworkLayer().(*layers.IPv6).DstIP = dstIP
			}
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}

			if pkt.TransportLayer() != nil && pkt.TransportLayer().(*layers.TCP) != nil {
				pkt.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(pkt.NetworkLayer())
			}

			// Serialize Packet to get raw bytes
			if err := gopacket.SerializePacket(buffer, options, pkt); err != nil {
				logger.Log(0, "Failed to serialize packet: ", err.Error())
				return nil, false
			}
			packetBytes := buffer.Bytes()
			return packetBytes, true
		}

	}
	return nil, false
}
