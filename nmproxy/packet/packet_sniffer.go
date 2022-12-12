package packet

// // use two sniffers one outbound and one for inbound, set filters accordingly
// var (
// 	snapshotLen int32         = 1024
// 	promiscuous bool          = false
// 	timeout     time.Duration = 1 * time.Nanosecond
// )

// func getOutboundHandler(ifaceName string) (*pcap.Handle, error) {

// 	// Open device
// 	handle, err := pcap.OpenLive(ifaceName, snapshotLen, promiscuous, timeout)
// 	if err != nil {
// 		logger.Log(1, "failed to get outbound sniffer for iface: ", ifaceName, err.Error())
// 		return nil, err
// 	}
// 	return handle, nil
// }

// func getInboundHandler(ifaceName string) (*pcap.Handle, error) {

// 	// Open device
// 	handle, err := pcap.OpenLive(ifaceName, snapshotLen, promiscuous, timeout)
// 	if err != nil {
// 		logger.Log(1, "failed to get outbound sniffer for iface: ", ifaceName, err.Error())
// 		return nil, err
// 	}
// 	return handle, nil
// }

// func startInBoundSniffer(ctx context.Context, wg *sync.WaitGroup) {
// 	defer wg.Done()
// 	inBoundHandler := config.GetCfg().SnifferCfg.InboundHandler
// 	packetSource := gopacket.NewPacketSource(inBoundHandler, config.GetCfg().SnifferCfg.InboundHandler.LinkType())
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return
// 		default:
// 			packet, err := packetSource.NextPacket()
// 			if err == nil {
// 				printPktInfo(packet, true)
// 				packet = routePkt(packet, true)
// 				if err := inBoundHandler.WritePacketData(packet.Data()); err != nil {
// 					logger.Log(0, "failed to inject pkt by inbound handler: ", err.Error())
// 				}
// 			}
// 		}

// 	}
// }

// func startOutBoundSniffer(ctx context.Context, wg *sync.WaitGroup) {
// 	defer wg.Done()
// 	outBoundHandler := config.GetCfg().SnifferCfg.OutBoundHandler
// 	packetSource := gopacket.NewPacketSource(outBoundHandler, config.GetCfg().SnifferCfg.OutBoundHandler.LinkType())
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return
// 		default:
// 			packet, err := packetSource.NextPacket()
// 			if err == nil {
// 				printPktInfo(packet, false)
// 				packet = routePkt(packet, false)
// 				if err := outBoundHandler.WritePacketData(packet.Data()); err != nil {
// 					logger.Log(0, "failed to inject pkt by outbound handler: ", err.Error())
// 				}
// 			}
// 		}

// 	}
// }

// // StartSniffer - sniffs the the interface
// func StartSniffer() error {

// 	defer func() {
// 		config.GetCfg().ResetSniffer()
// 	}()
// 	if config.GetCfg().IsIfaceNil() {
// 		return errors.New("iface is nil")
// 	}
// 	ifaceName := config.GetCfg().GetIface().Name
// 	logger.Log(1, "Starting Packet Sniffer for iface: ", ifaceName)
// 	outHandler, err := getOutboundHandler(ifaceName)
// 	if err != nil {
// 		return err
// 	}
// 	inHandler, err := getInboundHandler(ifaceName)
// 	if err != nil {
// 		return err
// 	}
// 	ctx, cancel := context.WithCancel(context.Background())
// 	config.GetCfg().InitSniffer(cancel)
// 	config.GetCfg().SetSnifferHandlers(inHandler, outHandler)
// 	config.GetCfg().SetBPFFilter()
// 	wg := &sync.WaitGroup{}
// 	wg.Add(1)
// 	go startInBoundSniffer(ctx, wg)
// 	wg.Add(1)
// 	go startOutBoundSniffer(ctx, wg)
// 	wg.Wait()
// 	return nil
// }

// func printPktInfo(packet gopacket.Packet, inbound bool) {

// 	ipLayer := packet.Layer(layers.LayerTypeIPv4)
// 	if ipLayer != nil {
// 		fmt.Println("IPv4 layer detected.  ", inbound)
// 		ip, _ := ipLayer.(*layers.IPv4)
// 		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
// 		fmt.Println("Protocol: ", ip.Protocol)
// 		fmt.Println()

// 	}
// 	// Check for errors
// 	if err := packet.ErrorLayer(); err != nil {
// 		fmt.Println("Error decoding some part of the packet:", err)
// 	}
// }

// func routePkt(pkt gopacket.Packet, inbound bool) gopacket.Packet {
// 	if pkt.NetworkLayer() != nil {
// 		flow := pkt.NetworkLayer().NetworkFlow()
// 		src, dst := flow.Endpoints()
// 		var srcIP, dstIP net.IP
// 		if inbound {
// 			if rInfo, found := config.GetCfg().GetRoutingInfo(src.String(), inbound); found {
// 				srcIP = rInfo.InternalIP
// 				dstIP = net.ParseIP(dst.String())
// 			}
// 		} else {
// 			if rInfo, found := config.GetCfg().GetRoutingInfo(dst.String(), inbound); found {
// 				srcIP = net.ParseIP(src.String())
// 				dstIP = rInfo.ExternalIP
// 			}
// 		}
// 		if pkt.NetworkLayer().(*layers.IPv4) != nil {
// 			pkt.NetworkLayer().(*layers.IPv4).SrcIP = srcIP
// 			pkt.NetworkLayer().(*layers.IPv4).DstIP = dstIP
// 		} else if pkt.NetworkLayer().(*layers.IPv6) != nil {
// 			pkt.NetworkLayer().(*layers.IPv6).SrcIP = srcIP
// 			pkt.NetworkLayer().(*layers.IPv6).DstIP = dstIP
// 		}
// 	}
// 	return pkt
// }
