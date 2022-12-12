package packet

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netmaker/logger"
)

// use two sniffers one outbound and one for inbound, set filters accordingly
var (
	snapshotLen int32         = 65048
	promiscuous bool          = true
	timeout     time.Duration = 1 * time.Microsecond
)

func getOutboundHandler(ifaceName string) (*pcap.Handle, error) {

	// Open device
	handle, err := pcap.OpenLive(ifaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		logger.Log(1, "failed to get outbound sniffer for iface: ", ifaceName, err.Error())
		return nil, err
	}
	return handle, nil
}

func getInboundHandler(ifaceName string) (*pcap.Handle, error) {

	// Open device
	handle, err := pcap.OpenLive(ifaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		logger.Log(1, "failed to get outbound sniffer for iface: ", ifaceName, err.Error())
		return nil, err
	}
	return handle, nil
}

func startInBoundSniffer(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	inBoundHandler := config.GetCfg().SnifferCfg.InboundHandler
	packetSource := gopacket.NewPacketSource(inBoundHandler, config.GetCfg().SnifferCfg.InboundHandler.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		default:
			packet, err := packetSource.NextPacket()
			if err == nil {
				printPktInfo(packet, true)
				routePkt(inBoundHandler, packet, true)
				// if err := inBoundHandler.WritePacketData(packet.Data()); err != nil {
				// 	logger.Log(0, "failed to inject pkt by inbound handler: ", err.Error())
				// }
			}
		}

	}
}

func startOutBoundSniffer(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	outBoundHandler := config.GetCfg().SnifferCfg.OutBoundHandler
	packetSource := gopacket.NewPacketSource(outBoundHandler, config.GetCfg().SnifferCfg.OutBoundHandler.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		default:
			packet, err := packetSource.NextPacket()
			if err == nil {
				printPktInfo(packet, false)
				routePkt(outBoundHandler, packet, true)
				// testpkt(packet, false)
				// if err := outBoundHandler.WritePacketData(packet.Data()); err != nil {
				// 	logger.Log(0, "failed to inject pkt by outbound handler: ", err.Error())
				// }
			}
		}

	}
}
func testpkt(packet gopacket.Packet, inbound bool) {

	flow := packet.NetworkLayer().NetworkFlow()
	src, dst := flow.Endpoints()
	logger.Log(0, "TESTING FROM: ", src.String(), " TO: ", dst.String(), " INBOUND: ", fmt.Sprint(inbound))
}

// StartSniffer - sniffs the the interface
func StartSniffer() error {
	var err error
	defer func() {
		config.GetCfg().ResetSniffer()
		if err != nil {
			logger.Log(0, "---------> Failed to start sniffer: ", err.Error())
		}
	}()
	if config.GetCfg().IsIfaceNil() {
		return errors.New("iface is nil")
	}
	ifaceName := config.GetCfg().GetIface().Name
	logger.Log(1, "Starting Packet Sniffer for iface: ", ifaceName)
	outHandler, err := getOutboundHandler(ifaceName)
	if err != nil {
		return err
	}
	inHandler, err := getInboundHandler(ifaceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	config.GetCfg().SetSnifferHandlers(inHandler, outHandler, cancel)
	err = config.GetCfg().SetBPFFilter()
	if err != nil {
		return err
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go startInBoundSniffer(ctx, wg)
	wg.Add(1)
	go startOutBoundSniffer(ctx, wg)
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

func routePkt(hander *pcap.Handle, pkt gopacket.Packet, inbound bool) {
	if pkt.NetworkLayer() != nil {
		flow := pkt.NetworkLayer().NetworkFlow()
		src, dst := flow.Endpoints()
		var srcIP, dstIP net.IP
		log.Println("========> FLOW: ", src.String(), " ---> ", dst.String())
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
		log.Println("SENDING FROMMM: ", srcIP.String(), " TO: ", dstIP.String(), " ", fmt.Sprint(inbound))
		if srcIP != nil && dstIP != nil {
			sendPktsV1(hander, pkt, srcIP, dstIP)
		}

	}

}

func sendPktsV1(handle *pcap.Handle, packet gopacket.Packet, srcIP, dstIP net.IP) {

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		//log.Printf("HEREEEEE FROM: %s TO %s", ip.SrcIP.String(), ip.DstIP.String())

		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp := icmpLayer.(*layers.ICMPv4)
			fmt.Println(icmp.Id)
			ip.SrcIP = srcIP
			ip.DstIP = dstIP

			options := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}

			// tcp.SetNetworkLayerForChecksum(ip)

			newBuffer := gopacket.NewSerializeBuffer()
			err := gopacket.SerializePacket(newBuffer, options, packet)
			if err != nil {
				panic(err)
			}
			outgoingPacket := newBuffer.Bytes()

			// fmt.Println("Hex dump of go packet serialization output:\n")
			// fmt.Println(hex.Dump(outgoingPacket))
			log.Println("-----------> SENDING PACKET FROM: ", ip.SrcIP.String(), " DST: ", ip.DstIP.String())
			err = handle.WritePacketData(outgoingPacket)
			if err != nil {
				log.Println("failed to write to interface: ", err)
			}
		}
	}
}
