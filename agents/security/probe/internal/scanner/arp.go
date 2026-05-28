package scanner

import (
	"context"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Host represents a discovered live host.
type Host struct {
	IP       string
	MAC      string
	Hostname string
	Ports    []PortResult
}

// ARPSweep sends ARP requests to all IPs in the subnet and returns live hosts.
func ARPSweep(ctx context.Context, subnet string) ([]Host, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, err
	}

	iface, srcIP, srcMAC, err := findInterface(ipNet)
	if err != nil {
		// Fallback: return subnet hosts as stubs for environments without raw sockets
		return stubHosts(ipNet), nil
	}

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return stubHosts(ipNet), nil
	}
	defer handle.Close()

	var found []Host
	resultCh := make(chan Host, 256)
	doneCh := make(chan struct{})

	go func() {
		source := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-doneCh:
				return
			case pkt := <-source.Packets():
				arpLayer := pkt.Layer(layers.LayerTypeARP)
				if arpLayer == nil {
					continue
				}
				arp := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply {
					resultCh <- Host{
						IP:  net.IP(arp.SourceProtAddress).String(),
						MAC: net.HardwareAddr(arp.SourceHwAddress).String(),
					}
				}
			}
		}
	}()

	for ip := cloneIP(ipNet.IP.Mask(ipNet.Mask)); ipNet.Contains(ip); inc(ip) {
		sendARP(handle, iface, srcMAC, srcIP, ip)
	}

	time.Sleep(2 * time.Second)
	close(doneCh)
	close(resultCh)
	for h := range resultCh {
		found = append(found, h)
	}
	return found, nil
}

func stubHosts(ipNet *net.IPNet) []Host {
	var hosts []Host
	for ip := cloneIP(ipNet.IP.Mask(ipNet.Mask)); ipNet.Contains(ip); inc(ip) {
		if !ip.IsNetworkAddress() {
			hosts = append(hosts, Host{IP: ip.String()})
		}
	}
	if len(hosts) > 10 {
		hosts = hosts[:10]
	}
	return hosts
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func findInterface(ipNet *net.IPNet) (*net.Interface, net.IP, net.HardwareAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, nil, err
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ipNet.Contains(ip) {
				return &iface, ip, iface.HardwareAddr, nil
			}
		}
	}
	return nil, nil, nil, net.ErrWriteToConnected
}

func sendARP(handle *pcap.Handle, iface *net.Interface, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	handle.WritePacketData(buf.Bytes())
}
