package router

import (
	"context"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netmaker/logger"
)

func getIngressOutboundHandler(ifaceName string) (*pcap.Handle, error) {

	// Open device
	handle, err := pcap.OpenLive(ifaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		logger.Log(1, "failed to get outbound router for iface: ", ifaceName, err.Error())
		return nil, err
	}

	return handle, nil
}

func getIngressInboundHandler(ifaceName string) (*pcap.Handle, error) {

	// Open device
	handle, err := pcap.OpenLive(ifaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		logger.Log(1, "failed to get outbound router for iface: ", ifaceName, err.Error())
		return nil, err
	}
	return handle, nil
}

func startIngressInBoundRouter(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	inBoundHandler := config.GetCfg().Router.IngressRouter.InboundHandler
	packetSource := gopacket.NewPacketSource(inBoundHandler, config.GetCfg().Router.IngressRouter.InboundHandler.LinkType())
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

func startIngressOutBoundRouter(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	outBoundHandler := config.GetCfg().Router.IngressRouter.OutBoundHandler
	packetSource := gopacket.NewPacketSource(outBoundHandler, config.GetCfg().Router.IngressRouter.OutBoundHandler.LinkType())
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
