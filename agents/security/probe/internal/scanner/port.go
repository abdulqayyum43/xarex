package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// PortResult holds the result of a single port scan.
type PortResult struct {
	Port    int
	Open    bool
	Service string
	Banner  string
}

// CommonPorts are the TCP ports always scanned.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888,
}

// ScanHosts runs port scans concurrently across all discovered hosts.
func ScanHosts(ctx context.Context, hosts []Host, ratePerSec int) []Host {
	sem := make(chan struct{}, ratePerSec/len(CommonPorts)+1)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := range hosts {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results := scanHost(ctx, hosts[idx].IP, sem)
			mu.Lock()
			hosts[idx].Ports = results
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	return hosts
}

func scanHost(ctx context.Context, ip string, sem chan struct{}) []PortResult {
	var results []PortResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, port := range CommonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := probePort(ip, p)
			if result.Open {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}

func probePort(ip string, port int) PortResult {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return PortResult{Port: port, Open: false}
	}
	defer conn.Close()

	result := PortResult{Port: port, Open: true, Service: guessService(port)}

	// Grab banner
	conn.SetDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		result.Banner = string(buf[:n])
	}

	return result
}

func guessService(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
		135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
		445: "smb", 993: "imaps", 995: "pop3s", 1723: "pptp",
		3306: "mysql", 3389: "rdp", 5900: "vnc",
		8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}
