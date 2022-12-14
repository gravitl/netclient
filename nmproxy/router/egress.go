package router

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netmaker/logger"
)

/*
	For egress -
	1. fetch all addresses from the wg interface
	2. two sniffers - 1) for WG interface --> with filter dst set to gateway interfaces --> then inject the pkt to GW interface
					  2) for GW interface --> with filter dst set to wg interface addrs --> then inject the pkt to Wg interface
*/

// StartEgress - sniffs the the interface
func StartEgress() error {
	var err error
	defer func() {
		config.GetCfg().ResetEgressRouter()
		if err != nil {
			logger.Log(0, "---------> Failed to start router: ", err.Error())
		}
		logger.Log(0, "-----> Stopping Router...")
	}()
	if config.GetCfg().IsIfaceNil() {
		return errors.New("iface is nil")
	}
	ifaceName := config.GetCfg().GetIface().Name
	logger.Log(1, "Starting egress packet router for iface: ", ifaceName)
	outHandler, err := getEgressOutboundHandler(ifaceName)
	if err != nil {
		return err
	}
	inHandler, err := getEgressInboundHandler("ens4")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	config.GetCfg().SetEgressRouterHandlers(inHandler, outHandler, cancel)
	err = config.GetCfg().SetEgressBPFFilter()
	if err != nil {
		return err
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go startEgressInBoundRouter(ctx, wg)
	wg.Add(1)
	go startEgressOutBoundRouter(ctx, wg)
	wg.Wait()
	return nil
}

func routePktEgress(pkt gopacket.Packet, inbound bool) ([]byte, bool) {
	if pkt.NetworkLayer() != nil {
		flow := pkt.NetworkLayer().NetworkFlow()
		src, dst := flow.Endpoints()
		var srcIP, dstIP net.IP
		srcIP = net.ParseIP(src.String())
		dstIP = net.ParseIP(dst.String())
		// if inbound {
		// 	if rInfo, found := config.GetCfg().GetEgressRoutingInfo(src.String(), inbound); found {
		// 		srcIP = rInfo.InternalIP
		// 		dstIP = net.ParseIP(dst.String())
		// 	}
		// } else {
		// 	//if rInfo, found := config.GetCfg().GetEgressRoutingInfo(dst.String(), inbound); found {
		// 		srcIP = net.ParseIP()
		// 		dstIP =
		// 	//}
		// }
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
