// Xarex Probe — Local Network Agent
//
// Deploys inside a client's network (Docker container or standalone binary),
// connects to the Xarex Cloud Brain via gRPC bidirectional stream, and executes
// authorised penetration-testing tasks dispatched by the Cloud Brain.
//
// Configuration (environment variables):
//
//	CLOUD_BRAIN_ADDR  – gRPC address of the Cloud Brain (default: localhost:50051)
//	ORG_ID            – Organisation identifier (required)
//	PROBE_ID          – Stable probe identifier; auto-generated UUID if not set
//	SCAN_SUBNETS      – Comma-separated CIDR subnets to include in auto-discovery
//	                    (default: auto-detected from local network interfaces)
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	grpcclient "github.com/xarex/probe/grpc"
	"github.com/xarex/probe/grpc/pb"
	"github.com/xarex/probe/modules"
	"github.com/xarex/probe/scanner"
)

const (
	probeVersion    = "1.0.0"
	heartbeatPeriod = 5 * time.Second
	resultChanSize  = 256
	taskChanSize    = 64
)

func main() {
	logger := buildLogger()
	logger.Info("Xarex Probe starting", "version", probeVersion)

	cfg := loadConfig(logger)

	// Build ProbeInfo with auto-detected network context.
	probeInfo, err := buildProbeInfo(cfg, logger)
	if err != nil {
		logger.Error("failed to build probe info", "error", err)
		os.Exit(1)
	}

	logger.Info("probe identity",
		"probe_id", probeInfo.ProbeId,
		"org_id", probeInfo.OrgId,
		"subnets", probeInfo.NetworkContext.Subnets,
		"hostname", probeInfo.NetworkContext.Hostname,
	)

	// Root context — cancelled on SIGTERM/SIGINT.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Channels for result/task exchange with the gRPC stream.
	resultChan := make(chan *pb.ScanResult, resultChanSize)
	taskChan := make(chan *pb.ScanTask, taskChanSize)

	// Connect to Cloud Brain.
	client := grpcclient.NewXarexClient(cfg.cloudBrainAddr, logger)
	if err := client.Connect(ctx); err != nil {
		logger.Error("failed to connect to cloud brain", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := client.Close(); err != nil {
			logger.Warn("error closing gRPC connection", "error", err)
		}
	}()

	// Register probe with the Cloud Brain.
	regResp, err := client.Register(ctx, probeInfo)
	if err != nil {
		logger.Error("probe registration failed", "error", err)
		os.Exit(1)
	}
	logger.Info("probe registered",
		"acknowledged", regResp.Acknowledged,
		"message", regResp.Message,
		"pending_tasks", len(regResp.PendingTasks),
	)

	// Enqueue any tasks the Cloud Brain already has for us.
	for _, t := range regResp.PendingTasks {
		select {
		case taskChan <- t:
		default:
			logger.Warn("task channel full; dropping pending task", "task_id", t.TaskId)
		}
	}

	// Start heartbeat goroutine.
	go heartbeatLoop(ctx, client, probeInfo, taskChan, logger)

	// Start bidirectional scan stream (manages its own reconnect loop).
	go client.StartScanStream(ctx, resultChan, taskChan)

	// Task dispatcher.
	dispatcher := modules.NewDispatcher(probeInfo.ProbeId, logger)

	logger.Info("probe ready, waiting for tasks")

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutdown signal received, draining...")
			// Allow in-flight results up to 10 seconds to flush.
			drain(resultChan, 10*time.Second, logger)
			logger.Info("probe shutdown complete")
			return

		case task, ok := <-taskChan:
			if !ok {
				logger.Warn("task channel closed unexpectedly")
				return
			}
			dispatcher.Dispatch(ctx, task, resultChan)
		}
	}
}

// ─────────────────────────────────────────────
//  Config
// ─────────────────────────────────────────────

type config struct {
	cloudBrainAddr string
	orgID          string
	probeID        string
	scanSubnets    []string
}

func loadConfig(logger *slog.Logger) config {
	// Load xarex.conf from same directory as the binary (or current dir).
	loadConfFile(logger)

	cfg := config{
		cloudBrainAddr: envOrDefault("CLOUD_BRAIN_ADDR", "localhost:50051"),
		orgID:          os.Getenv("ORG_ID"),
		probeID:        os.Getenv("PROBE_ID"),
	}

	if cfg.orgID == "" {
		logger.Error("ORG_ID not set. Edit xarex.conf and set ORG_ID to your organisation ID.")
		os.Exit(1)
	}

	if cfg.probeID == "" {
		cfg.probeID = uuid.NewString()
		logger.Info("PROBE_ID not set, generated ephemeral ID", "probe_id", cfg.probeID)
	}

	if raw := os.Getenv("SCAN_SUBNETS"); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				cfg.scanSubnets = append(cfg.scanSubnets, s)
			}
		}
	}

	return cfg
}

// loadConfFile reads xarex.conf (KEY=VALUE format) and sets any keys that
// are not already present as environment variables. This lets the binary run
// without manual env-var setup — users just edit the config file once.
func loadConfFile(logger *slog.Logger) {
	// Look in the directory of the executable first, then the working directory.
	candidates := []string{"xarex.conf"}
	if exe, err := os.Executable(); err == nil {
		candidates = append([]string{strings.TrimSuffix(exe, "/xarex-probe") + "/xarex.conf"}, candidates...)
	}

	var data []byte
	var err error
	for _, path := range candidates {
		data, err = os.ReadFile(path)
		if err == nil {
			logger.Info("loaded config file", "path", path)
			break
		}
	}
	if err != nil {
		return // No config file — rely purely on env vars
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// Strip surrounding quotes if present
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		// Only set if not already in environment (env vars take precedence)
		if os.Getenv(key) == "" && key != "" {
			os.Setenv(key, val)
		}
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ─────────────────────────────────────────────
//  ProbeInfo builder
// ─────────────────────────────────────────────

func buildProbeInfo(cfg config, logger *slog.Logger) (*pb.ProbeInfo, error) {
	hostname, _ := os.Hostname()

	subnets := cfg.scanSubnets
	if len(subnets) == 0 {
		detected, err := scanner.AutoDetectSubnets()
		if err != nil {
			logger.Warn("subnet auto-detection failed", "error", err)
		} else {
			subnets = detected
		}
	}

	gateways := scanner.AutoDetectGateways()

	return &pb.ProbeInfo{
		ProbeId:  cfg.probeID,
		OrgId:    cfg.orgID,
		Version:  probeVersion,
		Capabilities: []string{
			"host_discovery",
			"port_scan",
			"service_fingerprint",
			"smb_relay_check",
			"llmnr_poison_check",
			"vuln_check",
			"default_cred_test",
			"kerberoast_enum",
			"active_directory_enum",
			"ssl_tls_audit",
			"http_security_headers",
			"dns_zone_transfer",
			"exposed_admin_panel",
			"snmp_check",
			"rdp_security_check",
		},
		NetworkContext: &pb.NetworkContext{
			Subnets:  subnets,
			Gateways: gateways,
			Hostname: hostname,
			Os:       runtime.GOOS,
		},
	}, nil
}

// ─────────────────────────────────────────────
//  Heartbeat loop
// ─────────────────────────────────────────────

func heartbeatLoop(
	ctx context.Context,
	client *grpcclient.XarexClient,
	info *pb.ProbeInfo,
	taskChan chan<- *pb.ScanTask,
	logger *slog.Logger,
) {
	ticker := time.NewTicker(heartbeatPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			resp, err := client.Heartbeat(hbCtx, info)
			cancel()
			if err != nil {
				logger.Warn("heartbeat failed", "error", err)
				continue
			}
			logger.Debug("heartbeat ok",
				"ack", resp.Acknowledged,
				"pending_tasks", len(resp.PendingTasks),
			)
			// Dispatch any tasks returned in the heartbeat response
			for _, t := range resp.PendingTasks {
				select {
				case taskChan <- t:
				default:
					logger.Warn("task channel full; dropping heartbeat task", "task_id", t.TaskId)
				}
			}
		}
	}
}

// ─────────────────────────────────────────────
//  Logger
// ─────────────────────────────────────────────

func buildLogger() *slog.Logger {
	level := slog.LevelInfo
	if strings.EqualFold(os.Getenv("LOG_LEVEL"), "debug") {
		level = slog.LevelDebug
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     level,
		AddSource: level == slog.LevelDebug,
	})
	return slog.New(handler)
}

// ─────────────────────────────────────────────
//  Graceful drain
// ─────────────────────────────────────────────

// drain waits up to timeout for the resultChan to empty, logging any pending results.
func drain(resultChan chan *pb.ScanResult, timeout time.Duration, logger *slog.Logger) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		select {
		case <-deadline.C:
			logger.Warn("drain timeout reached, some results may be lost")
			return
		case result, ok := <-resultChan:
			if !ok {
				return
			}
			logger.Info("flushing result during shutdown",
				"task_id", result.TaskId,
				"success", result.Success,
			)
		default:
			// Channel is empty.
			return
		}
	}
}
