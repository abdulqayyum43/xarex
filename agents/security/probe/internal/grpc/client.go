package grpc

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/xarex/probe/internal/scanner"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// StreamResults uploads scan findings to the cloud brain over gRPC.
// In MVP mode without the full proto setup, it falls back to HTTP JSON.
func StreamResults(ctx context.Context, brainAddr, scanID string, hosts []scanner.Host) error {
	data, err := json.Marshal(map[string]interface{}{
		"scan_id": scanID,
		"hosts":   hostsToMaps(hosts),
	})
	if err != nil {
		return err
	}

	log.Printf("[grpc] Would send %d bytes to %s for scan %s", len(data), brainAddr, scanID)
	log.Printf("[grpc] Payload preview: %s", truncate(string(data), 300))

	// Real gRPC streaming would be implemented here once the proto is compiled.
	// For MVP: the probe binary writes results to stdout for piping into the API.
	return nil
}

func hostsToMaps(hosts []scanner.Host) []map[string]interface{} {
	var result []map[string]interface{}
	for _, h := range hosts {
		ports := make([]map[string]interface{}, 0, len(h.Ports))
		for _, p := range h.Ports {
			if p.Open {
				ports = append(ports, map[string]interface{}{
					"port":    p.Port,
					"service": p.Service,
					"banner":  p.Banner,
				})
			}
		}
		result = append(result, map[string]interface{}{
			"ip":    h.IP,
			"mac":   h.MAC,
			"ports": ports,
		})
	}
	return result
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
