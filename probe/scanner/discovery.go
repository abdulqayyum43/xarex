// Package scanner provides host discovery, port scanning, and service fingerprinting.
package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/xarex/probe/grpc/pb"
)

const (
	arpTimeout     = 2 * time.Second
	icmpTimeout    = 1 * time.Second
	arpWorkers     = 50
	icmpWorkers    = 200
	tcpProbeTimeout = 150 * time.Millisecond // reduced from 300ms for faster subnet sweeps
)

// DiscoveryScanner performs host discovery against a subnet using ARP (Layer 2)
// with an ICMP ping-sweep fallback when raw socket access is unavailable.
type DiscoveryScanner struct {
	logger *slog.Logger
}

// NewDiscoveryScanner returns a ready-to-use DiscoveryScanner.
func NewDiscoveryScanner(logger *slog.Logger) *DiscoveryScanner {
	return &DiscoveryScanner{logger: logger}
}

// arpDeadline is the hard maximum we allow arpScan to run before we give up
// and fall through to ICMP. Prevents pcap from hanging indefinitely in WSL2
// or other virtual environments where the network stack is unusual.
const arpDeadline = 15 * time.Second

// Scan discovers live hosts in the given CIDR subnet.
// It prefers ARP scanning (accurate, fast) and falls back to ICMP on failure.
func (s *DiscoveryScanner) Scan(ctx context.Context, subnet string) ([]*pb.Host, error) {
	ips, err := expandCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("expand CIDR %q: %w", subnet, err)
	}
	s.logger.Info("starting host discovery", "subnet", subnet, "hosts_to_probe", len(ips))

	// Run ARP with a hard deadline so it never hangs in WSL2/virtual envs.
	arpCtx, arpCancel := context.WithTimeout(ctx, arpDeadline)
	hosts, arpErr := s.arpScan(arpCtx, subnet, ips)
	arpCancel()

	if arpErr != nil || len(hosts) == 0 {
		// Fall back to ICMP+TCP probe when:
		//   - ARP returned an error (no pcap/root access)
		//   - ARP succeeded but found 0 hosts (WSL/virtual NICs don't respond to ARP)
		//   - ARP timed out (arpDeadline exceeded — typical in WSL2)
		if arpErr != nil {
			s.logger.Warn("ARP scan unavailable, falling back to ICMP/TCP", "reason", arpErr)
		} else {
			s.logger.Info("ARP returned 0 hosts (virtual/WSL NIC?), falling back to ICMP/TCP")
		}
		hosts, err = s.icmpScan(ctx, ips)
		if err != nil {
			return nil, fmt.Errorf("icmp scan: %w", err)
		}
	}

	// Enrich with reverse DNS.
	for _, h := range hosts {
		h.Hostname = reverseLookup(h.Ip)
	}

	s.logger.Info("host discovery complete", "subnet", subnet, "live_hosts", len(hosts))
	return hosts, nil
}

// AutoDetectSubnets returns the subnets reachable from all non-loopback interfaces.
func AutoDetectSubnets() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var subnets []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if cidr, ok := addr.(*net.IPNet); ok && cidr.IP.To4() != nil {
				subnets = append(subnets, cidr.String())
			}
		}
	}
	return subnets, nil
}

// AutoDetectGateways returns the default gateway IPs (best-effort, platform-specific).
func AutoDetectGateways() []string {
	// Simplified: return the .1 address of each detected subnet.
	subnets, _ := AutoDetectSubnets()
	var gateways []string
	for _, s := range subnets {
		ip, _, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		// Increment network address by 1 to get the typical gateway.
		n := binary.BigEndian.Uint32(v4)
		n = (n & 0xFFFFFF00) + 1
		gw := make(net.IP, 4)
		binary.BigEndian.PutUint32(gw, n)
		gateways = append(gateways, gw.String())
	}
	return gateways
}

// ─────────────────────────────────────────────
//  ARP scanner
// ─────────────────────────────────────────────

// arpScan uses gopacket/pcap to send ARP requests and collect replies.
func (s *DiscoveryScanner) arpScan(ctx context.Context, subnet string, targets []string) ([]*pb.Host, error) {
	iface, srcIP, srcMAC, err := findInterfaceForSubnet(subnet)
	if err != nil {
		return nil, fmt.Errorf("find interface for %s: %w", subnet, err)
	}

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap open live: %w", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("set BPF filter: %w", err)
	}

	discovered := make(map[string]*pb.Host)
	var mu sync.Mutex

	// Receiver goroutine.
	recvCtx, cancelRecv := context.WithCancel(ctx)
	defer cancelRecv()

	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-recvCtx.Done():
				return
			case pkt, ok := <-src.Packets():
				if !ok {
					return
				}
				arpLayer := pkt.Layer(layers.LayerTypeARP)
				if arpLayer == nil {
					continue
				}
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation != layers.ARPReply {
					continue
				}
				ip := net.IP(arp.SourceProtAddress).String()
				mac := net.HardwareAddr(arp.SourceHwAddress).String()
				mu.Lock()
				if _, seen := discovered[ip]; !seen {
					discovered[ip] = &pb.Host{
						Ip:         ip,
						MacAddress: mac,
						IsAlive:    true,
					}
				}
				mu.Unlock()
			}
		}
	}()

	// Send ARP requests with bounded concurrency.
	sem := make(chan struct{}, arpWorkers)
	var wg sync.WaitGroup
arpLoop:
	for _, target := range targets {
		select {
		case <-ctx.Done():
			break arpLoop
		default:
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			_ = sendARPRequest(handle, srcIP, srcMAC, ip)
		}(target)
	}
	wg.Wait()

	// Give replies time to arrive.
	timer := time.NewTimer(arpTimeout)
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
	}
	cancelRecv()
	<-recvDone

	mu.Lock()
	defer mu.Unlock()
	hosts := make([]*pb.Host, 0, len(discovered))
	for _, h := range discovered {
		hosts = append(hosts, h)
	}
	return hosts, nil
}

func sendARPRequest(handle *pcap.Handle, srcIP net.IP, srcMAC net.HardwareAddr, targetIP string) error {
	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		return fmt.Errorf("invalid target IP: %s", targetIP)
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return fmt.Errorf("serialize ARP: %w", err)
	}
	return handle.WritePacketData(buf.Bytes())
}

// findInterfaceForSubnet returns the pcap interface name, source IP, and MAC
// that has an address within the given subnet.
func findInterfaceForSubnet(subnet string) (string, net.IP, net.HardwareAddr, error) {
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", nil, nil, fmt.Errorf("parse CIDR: %w", err)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, nil, fmt.Errorf("list interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if network.Contains(ipNet.IP) || ipNet.Contains(network.IP) {
				// On Linux the pcap device name matches iface.Name.
				// On macOS it may differ; pcap.FindAllDevs handles that.
				pcapName := iface.Name
				if runtime.GOOS == "windows" {
					pcapName = findWinPcapDevice(iface.Name)
				}
				return pcapName, ipNet.IP.To4(), iface.HardwareAddr, nil
			}
		}
	}
	return "", nil, nil, fmt.Errorf("no interface found for subnet %s", subnet)
}

// findWinPcapDevice returns the WinPcap/npcap device name matching the given
// friendly interface name on Windows.
func findWinPcapDevice(friendlyName string) string {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return friendlyName
	}
	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			_ = addr
		}
		if dev.Name == friendlyName || containsString(dev.Description, friendlyName) {
			return dev.Name
		}
	}
	return friendlyName
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────
//  ICMP ping sweep fallback
// ─────────────────────────────────────────────

// icmpScan performs a parallel ICMP echo sweep using net.Dial("ip4:icmp", ...).
// This requires CAP_NET_RAW on Linux or running as Administrator on Windows.
// As a further fallback it uses a TCP connect to port 80/443 to test liveness.
func (s *DiscoveryScanner) icmpScan(ctx context.Context, targets []string) ([]*pb.Host, error) {
	var (
		mu      sync.Mutex
		hosts   []*pb.Host
		sem     = make(chan struct{}, icmpWorkers)
		wg      sync.WaitGroup
	)

	canICMP := os.Getuid() == 0 || runtime.GOOS == "windows"
	localIPs := localInterfaceIPs()

outer:
	for _, target := range targets {
		select {
		case <-ctx.Done():
			break outer
		default:
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Always treat the probe's own IP as alive.
			if localIPs[ip] {
				mu.Lock()
				hosts = append(hosts, &pb.Host{Ip: ip, IsAlive: true})
				mu.Unlock()
				return
			}

			alive := false
			if canICMP {
				alive = icmpPing(ctx, ip)
			}
			if !alive {
				// System ping works on most Linux distros without root
				// (ping binary has cap_net_raw or setuid) — best fallback for WSL2.
				alive = pingCommand(ctx, ip)
			}
			if !alive {
				alive = tcpProbe(ctx, ip)
			}
			if alive {
				mu.Lock()
				hosts = append(hosts, &pb.Host{Ip: ip, IsAlive: true})
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	return hosts, nil
}

// icmpPing sends a single ICMP echo request and waits for a reply.
func icmpPing(ctx context.Context, ip string) bool {
	deadline, ok := ctx.Deadline()
	timeout := icmpTimeout
	if ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}

	conn, err := net.DialTimeout("ip4:icmp", ip, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Minimal ICMP echo request (type=8, code=0).
	msg := []byte{8, 0, 0, 0, 0, 1, 0, 1, 'H', 'i'}
	cs := icmpChecksum(msg)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs)

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	return err == nil
}

// pingCommand uses the system ping binary to test liveness.
// This works on WSL2/Linux without root because /bin/ping has cap_net_raw or
// the setuid bit. It is a reliable fallback when raw ICMP sockets are blocked.
func pingCommand(ctx context.Context, ip string) bool {
	pingBin, err := exec.LookPath("ping")
	if err != nil {
		return false
	}

	var args []string
	switch runtime.GOOS {
	case "windows":
		args = []string{"-n", "1", "-w", "1000", ip}
	case "darwin":
		args = []string{"-c", "1", "-W", "1000", ip}
	default: // linux / WSL2
		args = []string{"-c", "1", "-W", "1", ip}
	}

	pCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(pCtx, pingBin, args...)
	// Suppress stdout/stderr to keep probe output clean.
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpProbe tests host liveness via TCP.
// A successful connection OR an immediate ECONNREFUSED both confirm the host exists.
// Only a timeout means the host is unreachable.
func tcpProbe(ctx context.Context, ip string) bool {
	d := net.Dialer{Timeout: tcpProbeTimeout}
	ports := []int{80, 443, 22, 445, 8080, 3389, 50051, 8005, 5432, 3306, 21, 25, 8443,
		23, 53, 135, 139, 161, 389, 636, 993, 995, 1433, 1521, 3000, 4443, 5900, 6379, 8000, 8888, 9200, 27017}
	for _, port := range ports {
		conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
		if err == nil {
			conn.Close()
			return true
		}
		// ECONNREFUSED = port closed but host IS alive and reachable
		if isConnRefused(err) {
			return true
		}
	}
	return false
}

// isConnRefused returns true if the error is a TCP connection refused.
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "connection refused") || strings.Contains(s, "refused")
}

// localInterfaceIPs returns a set of all IPs assigned to local network interfaces.
func localInterfaceIPs() map[string]bool {
	result := map[string]bool{"127.0.0.1": true}
	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if v4 := ipNet.IP.To4(); v4 != nil {
					result[v4.String()] = true
				}
			}
		}
	}
	return result
}

// ─────────────────────────────────────────────
//  Utility
// ─────────────────────────────────────────────

// expandCIDR returns all usable host IPs in the given CIDR block.
// For /32 (single-host) CIDRs the host IP itself is returned as-is.
func expandCIDR(cidr string) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR: %w", err)
	}

	// /32 — the single address IS the host; skip network/broadcast logic.
	ones, bits := network.Mask.Size()
	if ones == bits { // e.g. /32 for IPv4
		return []string{ip.String()}, nil
	}

	var ips []string
	broadcast := broadcastAddr(network)
	for cur := cloneIP(ip.Mask(network.Mask)); network.Contains(cur); incrementIP(cur) {
		// Skip network address and broadcast address.
		if cur.Equal(network.IP) || cur.Equal(broadcast) {
			continue
		}
		ips = append(ips, cur.String())
	}
	return ips, nil
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func broadcastAddr(network *net.IPNet) net.IP {
	ip := network.IP.To4()
	mask := network.Mask
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}

func reverseLookup(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := names[0]
	// Strip trailing dot.
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
