package router

import (
	"context"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netmaker/logger"
)

func getEgressOutboundHandler(ifaceName string) (*pcap.Handle, error) {

	// Open device
	handle, err := pcap.OpenLive(ifaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		logger.Log(1, "failed to get outbound router for iface: ", ifaceName, err.Error())
		return nil, err
	}

	return handle, nil
}

func getEgressInboundHandler(ifaceName string) (*pcap.Handle, error) {

	// Open device
	handle, err := pcap.OpenLive(ifaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		logger.Log(1, "failed to get outbound router for iface: ", ifaceName, err.Error())
		return nil, err
	}
	return handle, nil
}

func startEgressInBoundRouter(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	inBoundHandler := config.GetCfg().Router.EgressRouter.InboundHandler
	outBoundHandler := config.GetCfg().Router.EgressRouter.OutBoundHandler
	packetSource := gopacket.NewPacketSource(inBoundHandler, config.GetCfg().Router.EgressRouter.InboundHandler.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		default:
			packet, err := packetSource.NextPacket()
			if err == nil {
				printPktInfo(packet, true)
				// pktBytes, shouldRoute := routePktEgress(packet, true)
				// if !shouldRoute {
				// 	continue
				// }
				if err := outBoundHandler.WritePacketData(packet.Data()); err != nil {
					logger.Log(0, "failed to inject pkt by inbound handler: ", err.Error())
				}
			} else {
				logger.Log(1, "failed to read next packet: ", err.Error())
			}
		}

	}
}

func startEgressOutBoundRouter(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	inBoundHandler := config.GetCfg().Router.EgressRouter.InboundHandler
	outBoundHandler := config.GetCfg().Router.EgressRouter.OutBoundHandler
	packetSource := gopacket.NewPacketSource(outBoundHandler, config.GetCfg().Router.EgressRouter.OutBoundHandler.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		default:
			packet, err := packetSource.NextPacket()
			if err == nil {
				printPktInfo(packet, false)
				// pktBytes, shouldRoute := routePktEgress(packet, false)
				// if !shouldRoute {
				// 	continue
				// }
				if err := inBoundHandler.WritePacketData(packet.Data()); err != nil {
					logger.Log(0, "failed to inject pkt by outbound handler: ", err.Error())
				}

			}
		}

	}
}
