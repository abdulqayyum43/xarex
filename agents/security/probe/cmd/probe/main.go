package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/xarex/probe/internal/grpc"
	"github.com/xarex/probe/internal/scanner"
)

func main() {
	subnet := flag.String("subnet", "", "Target subnet in CIDR notation, e.g. 192.168.1.0/24")
	brainAddr := flag.String("brain", "localhost:50051", "Cloud brain gRPC address")
	scanID := flag.String("scan-id", "", "Scan ID assigned by cloud brain")
	rateLimit := flag.Int("rate", 1000, "Port scan packets per second")
	flag.Parse()

	if *subnet == "" || *scanID == "" {
		fmt.Fprintln(os.Stderr, "Usage: probe -subnet 192.168.1.0/24 -scan-id <id> [-brain addr] [-rate n]")
		os.Exit(1)
	}

	log.Printf("[xarex-probe] Starting scan %s on subnet %s", *scanID, *subnet)

	ctx := context.Background()

	// Phase 1: ARP discovery
	log.Println("[xarex-probe] Phase 1: ARP host discovery")
	hosts, err := scanner.ARPSweep(ctx, *subnet)
	if err != nil {
		log.Fatalf("ARP sweep failed: %v", err)
	}
	log.Printf("[xarex-probe] Found %d live hosts", len(hosts))

	// Phase 2: Port scan + service fingerprint
	log.Println("[xarex-probe] Phase 2: Port scanning")
	results := scanner.ScanHosts(ctx, hosts, *rateLimit)

	// Phase 3: Stream results to cloud brain
	log.Printf("[xarex-probe] Phase 3: Uploading %d host results to brain at %s", len(results), *brainAddr)
	if err := grpc.StreamResults(ctx, *brainAddr, *scanID, results); err != nil {
		log.Fatalf("Failed to stream results: %v", err)
	}

	log.Println("[xarex-probe] Done.")
}
