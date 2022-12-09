package packet

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gravitl/netmaker/logger"
)

// StartSniffer - sniffs the packets coming out of the interface
func StartSniffer(ctx context.Context, ifaceName, ingGwAddr, extInternalIP, extClientAddr string) {
	logger.Log(1, "Starting Packet Sniffer for iface: ", ifaceName, ingGwAddr, extInternalIP, extClientAddr)
	var (
		snapshotLen int32 = 1024
		promiscuous bool  = false
		err         error
		timeout     time.Duration = 1 * time.Microsecond
		handle      *pcap.Handle
	)
<<<<<<< HEAD
	toExtClientConn, err := net.DialIP("ip:icmp", &net.IPAddr{
		IP: net.ParseIP(ingGwAddr),
	}, &net.IPAddr{
		IP: net.ParseIP(extClientAddr),
	})
	if err != nil {
		log.Println("QUTIING SNIFFER: ", err)
		return
	}
	toPeer, err := net.DialIP("ip:icmp", &net.IPAddr{
		IP: net.ParseIP(extInternalIP),
	}, &net.IPAddr{
		IP: net.ParseIP("10.235.166.2"),
	})
	if err != nil {
		log.Println("1 QUTIING SNIFFER: ", err)
		return
	}
=======
	// toExtClientConn, err := net.DialIP("ip:icmp", &net.IPAddr{
	// 	IP: net.ParseIP(ingGwAddr),
	// }, &net.IPAddr{
	// 	IP: net.ParseIP(extClientAddr),
	// })
	// if err != nil {
	// 	log.Println("QUTIING SNIFFER: ", err)
	// 	return
	// }
	// toPeer, err := net.DialIP("ip:icmp", &net.IPAddr{
	// 	IP: net.ParseIP(extInternalIP),
	// }, &net.IPAddr{
	// 	IP: net.ParseIP("10.235.166.1"),
	// })
	// if err != nil {
	// 	log.Println("1 QUTIING SNIFFER: ", err)
	// 	return
	// }
>>>>>>> 6c61983991e6e31de507cb4d046c27d1b062fa0a
	// Open device
	handle, err = pcap.OpenLive(ifaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		logger.Log(1, "failed to start sniffer for iface: ", ifaceName, err.Error())
		return
	}
	// if err := handle.SetBPFFilter(fmt.Sprintf("src %s and port %d", extClientAddr, port)); err != nil {
	// 	logger.Log(1,"failed to set bpf filter: ", err)
	// 	return
	// }
	defer handle.Close()

	// var tcp layers.TCP
	// var icmp layers.ICMPv4
	// var udp layers.UDP
	// parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &udp, &tcp, &icmp)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			logger.Log(1, fmt.Sprint("Stopping packet sniffer for iface: ", ifaceName))
			return
		default:
			packet, err := packetSource.NextPacket()
			if err == nil {
				//processPkt(ifaceName, packet)
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer != nil {
					fmt.Println("IPv4 layer detected.")
					ip, _ := ipLayer.(*layers.IPv4)

					// IP layer variables:
					// Version (Either 4 or 6)
					// IHL (IP Header Length in 32-bit words)
					// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
					// Checksum, SrcIP, DstIP

					// if (ip.SrcIP.String() == extClientAddr && ip.DstIP.String() != ingGwAddr) ||
					// 	(ip.DstIP.String() == extClientAddr && ip.SrcIP.String() != ingGwAddr) {

					// 	logger.Log(1, "-----> Fowarding PKT From: ", ip.SrcIP.String(), " to: ", ip.DstIP.String())
					// 	c, err := net.Dial("ip", ip.DstIP.String())
					// 	if err == nil {
					// 		c.Write(ip.Payload)
					// 		c.Close()
					// 	} else {
					// 		logger.Log(1, "------> Failed to forward packet from sniffer: ", err.Error())

					// 	}
					// }
<<<<<<< HEAD
					if ip.SrcIP.String() == extClientAddr && ip.DstIP.String() == "10.235.166.2" {
						fmt.Println("############ SENDING TO PEER #############")
						fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
						fmt.Println("Protocol: ", ip.Protocol.String())
						_, err := toPeer.Write(ip.Payload)
						if err != nil {
							log.Println("falied to send it to peer from ext cleint", err)
						}
					} else if ip.SrcIP.String() == "10.235.166.2" && ip.DstIP.String() == extInternalIP {
						fmt.Println("########## SENDING TO EXT ###############")
						fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
						fmt.Println("Protocol: ", ip.Protocol.String())

						_, err := toExtClientConn.Write(ip.Payload)
						if err != nil {
							log.Println("falied to send it to  ext cleint", err)
						}
=======
					if ip.SrcIP.String() == extClientAddr && ip.DstIP.String() == "10.235.166.1" {
						// fmt.Println("############ SENDING TO PEER #############")
						// fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
						// fmt.Println("Protocol: ", ip.Protocol.String())
						// _, err := toPeer.Write(ip.Payload)
						// if err != nil {
						// 	log.Println("falied to send it to peer from ext cleint", err)
						// }
						sendPktsV1(handle, packet, ip.SrcIP.String(), ip.DstIP.String(), ingGwAddr, extInternalIP, extClientAddr)
					} else if ip.SrcIP.String() == "10.235.166.1" && ip.DstIP.String() == extInternalIP {
						fmt.Println("########## SENDING TO DST EXT ###############")
						// fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
						// fmt.Println("Protocol: ", ip.Protocol.String())

						// _, err := toExtClientConn.Write(ip.Payload)
						// if err != nil {
						// 	log.Println("falied to send it to  ext cleint", err)
						// }
						sendPktsV1(handle, packet, ip.SrcIP.String(), ip.DstIP.String(), ingGwAddr, extInternalIP, extClientAddr)
>>>>>>> 6c61983991e6e31de507cb4d046c27d1b062fa0a
					}

					fmt.Println("#########################")
				}
			}
		}

	}
}
<<<<<<< HEAD
=======
func sendPktsV1(handle *pcap.Handle, pkt gopacket.Packet, from, to, ingGwAddr, extInternalIP, extClientAddr string) {
	packetData := pkt.Data()

	// fmt.Println("Hex dump of real IP packet taken as input:\n")
	// fmt.Println(hex.Dump(packetData))

	packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)
	// packet := pkt
	//log.Println("-----------> SENDING ICMP PACKET FROM: ", from, " DST: ", to)
	// err := handle.WritePacketData(pkt.Data())
	// if err != nil {
	// 	log.Println("failed to write to interface: ", err)
	// }
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		log.Printf(" ACTUAL HEREEEEE FROM: %s TO %s", ip.SrcIP.String(), ip.DstIP.String())
		srcIp := ""
		dstIp := ""
		if ip.SrcIP.String() == extClientAddr {
			srcIp = extInternalIP
			dstIp = to
		}
		if ip.DstIP.String() == extInternalIP {
			srcIp = from
			dstIp = extClientAddr
		}
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp := icmpLayer.(*layers.ICMPv4)
			fmt.Println(icmp.Id)
			ip.SrcIP = net.ParseIP(srcIp)
			ip.DstIP = net.ParseIP(dstIp)
			//log.Printf(" SENDING HEREEEEE FROM: %s TO %s", ip.SrcIP.String(), ip.DstIP.String())
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
			log.Println("-----------> SENDING ICMP PACKET FROM: ", ip.SrcIP.String(), " DST: ", ip.DstIP.String())
			err = handle.WritePacketData(outgoingPacket)
			if err != nil {
				log.Println("failed to write to interface: ", err)
			}
		}
	}
}
>>>>>>> 6c61983991e6e31de507cb4d046c27d1b062fa0a

func processPkt(iface string, packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	// ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	// if ethernetLayer != nil {
	// 	fmt.Println("Ethernet layer detected.")
	// 	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
	// 	fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
	// 	fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
	// 	// Ethernet type is typically IPv4 but could be ARP or other
	// 	fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
	// 	fmt.Println()
	// }

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()

	}

	// udpLayer := packet.Layer(layers.LayerTypeUDP)
	// if udpLayer != nil {
	// 	udp, _ := udpLayer.(*layers.UDP)
	// 	fmt.Printf("UDP: From port %d to %d\n", udp.SrcPort, udp.DstPort)
	// 	fmt.Println()
	// }

	// // Iterate over all layers, printing out each layer type
	// fmt.Println("All packet layers:")
	// for _, layer := range packet.Layers() {
	// 	fmt.Println("- ", layer.LayerType())
	// }

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	// applicationLayer := packet.ApplicationLayer()
	// if applicationLayer != nil {
	// 	fmt.Println("Application layer/Payload found.")
	// 	fmt.Printf("%s\n", applicationLayer.Payload())

	// 	// Search for a string inside the payload
	// 	if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
	// 		fmt.Println("HTTP found!")
	// 	}
	// }

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
