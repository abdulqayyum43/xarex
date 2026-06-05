// Package modules contains the task dispatcher that routes incoming ScanTask
// messages from the Cloud Brain to the appropriate scanner or checker module.
package modules

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xarex/probe/grpc/pb"
	"github.com/xarex/probe/relay"
	"github.com/xarex/probe/scanner"
)

// Port → service name used when service param is missing
var portServiceHints = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	80: "http", 389: "ldap", 443: "https", 445: "smb",
	587: "smtp", 636: "ldaps", 6379: "redis",
	9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
	3306: "mysql", 1433: "mssql", 5432: "postgresql",
	3389: "rdp", 5900: "vnc", 10000: "webmin",
}

// Dispatcher routes ScanTask messages to the correct module and assembles
// a ScanResult to push back to the Cloud Brain.
type Dispatcher struct {
	probeID        string
	logger         *slog.Logger
	discovery      *scanner.DiscoveryScanner
	portScanner    *scanner.PortScanner
	fingerprint    *scanner.Fingerprinter
	smbChecker     *relay.SMBRelayChecker
	llmnrCheck     *relay.LLMNRChecker
	credChecker    *scanner.CredChecker
	adEnumerator   *scanner.ADEnumerator
	sslAuditor     *scanner.SSLAuditScanner
	httpHeaders    *scanner.HTTPHeaderScanner
	dnsZoneXfer    *scanner.DNSZoneTransferScanner
	adminPanel     *scanner.AdminPanelScanner
	snmpChecker    *scanner.SNMPChecker
	rdpChecker     *scanner.RDPChecker
	webAppScanner  *scanner.WebAppScanner
	nucleiScanner  *scanner.NucleiScanner
}

// NewDispatcher wires up all sub-modules and returns a ready Dispatcher.
func NewDispatcher(probeID string, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{
		probeID:       probeID,
		logger:        logger,
		discovery:     scanner.NewDiscoveryScanner(logger),
		portScanner:   scanner.NewPortScanner(logger),
		fingerprint:   scanner.NewFingerprinter(logger),
		smbChecker:    relay.NewSMBRelayChecker(logger),
		llmnrCheck:    relay.NewLLMNRChecker(logger),
		credChecker:   scanner.NewCredChecker(logger),
		adEnumerator:  scanner.NewADEnumerator(logger),
		sslAuditor:    scanner.NewSSLAuditScanner(logger),
		httpHeaders:   scanner.NewHTTPHeaderScanner(logger),
		dnsZoneXfer:   scanner.NewDNSZoneTransferScanner(logger),
		adminPanel:    scanner.NewAdminPanelScanner(logger),
		snmpChecker:   scanner.NewSNMPChecker(logger),
		rdpChecker:    scanner.NewRDPChecker(logger),
		webAppScanner: scanner.NewWebAppScanner(logger),
		nucleiScanner: scanner.NewNucleiScanner(logger),
	}
}

// Dispatch executes task asynchronously and sends the result to resultChan.
// A context with the task's timeout is derived from the parent ctx.
func (d *Dispatcher) Dispatch(ctx context.Context, task *pb.ScanTask, resultChan chan<- *pb.ScanResult) {
	go func() {
		result := d.execute(ctx, task)
		select {
		case resultChan <- result:
		case <-ctx.Done():
			d.logger.Warn("result dropped: context cancelled", "task_id", task.TaskId)
		}
	}()
}

// execute runs the task synchronously and returns a ScanResult.
func (d *Dispatcher) execute(ctx context.Context, task *pb.ScanTask) *pb.ScanResult {
	start := time.Now()
	taskCtx := ctx

	// Apply per-task timeout if specified.
	if task.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		taskCtx, cancel = context.WithTimeout(ctx, time.Duration(task.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	d.logger.Info("dispatching task",
		"task_id", task.TaskId,
		"scan_id", task.ScanId,
		"type", task.Type.String(),
		"timeout_s", task.TimeoutSeconds,
	)

	findings, err := d.route(taskCtx, task)

	result := &pb.ScanResult{
		TaskId:     task.TaskId,
		ScanId:     task.ScanId,
		ProbeId:    d.probeID,
		Success:    err == nil,
		DurationMs: time.Since(start).Milliseconds(),
		Timestamp:  time.Now().UnixMilli(),
		Findings:   findings,
	}
	if err != nil {
		result.Error = err.Error()
		d.logger.Warn("task failed",
			"task_id", task.TaskId,
			"type", task.Type.String(),
			"error", err,
		)
	} else {
		d.logger.Info("task complete",
			"task_id", task.TaskId,
			"type", task.Type.String(),
			"findings", len(findings),
			"duration_ms", result.DurationMs,
		)
	}
	return result
}

// route dispatches to the correct module based on task type.
func (d *Dispatcher) route(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	switch task.Type {
	case pb.TaskType_HOST_DISCOVERY:
		return d.handleHostDiscovery(ctx, task)

	case pb.TaskType_PORT_SCAN:
		return d.handlePortScan(ctx, task)

	case pb.TaskType_SERVICE_FINGERPRINT:
		return d.handleFingerprint(ctx, task)

	case pb.TaskType_SMB_RELAY_CHECK:
		return d.handleSMBRelayCheck(ctx, task)

	case pb.TaskType_LLMNR_POISON_CHECK:
		return d.handleLLMNRCheck(ctx, task)

	case pb.TaskType_VULN_CHECK:
		return d.handleVulnCheck(ctx, task)

	case pb.TaskType_DEFAULT_CRED_TEST:
		return d.handleDefaultCredTest(ctx, task)

	case pb.TaskType_KERBEROAST_ENUM:
		return d.handleADEnum(ctx, task)

	case pb.TaskType_ACTIVE_DIRECTORY_ENUM:
		return d.handleADEnum(ctx, task)

	case pb.TaskType_SSL_TLS_AUDIT:
		return d.handleSSLAudit(ctx, task)

	case pb.TaskType_HTTP_SECURITY_HEADERS:
		return d.handleHTTPHeaders(ctx, task)

	case pb.TaskType_DNS_ZONE_TRANSFER:
		return d.handleDNSZoneTransfer(ctx, task)

	case pb.TaskType_EXPOSED_ADMIN_PANEL:
		return d.handleAdminPanel(ctx, task)

	case pb.TaskType_SNMP_COMMUNITY_STRING:
		return d.handleSNMP(ctx, task)

	case pb.TaskType_RDP_SECURITY_CHECK:
		return d.handleRDP(ctx, task)

	case pb.ScanTask_WEB_APP_SCAN:
		return d.handleWebAppScan(ctx, task)

	case pb.TaskType_NUCLEI_SCAN:
		return d.handleNucleiScan(ctx, task)

	case pb.TaskType_CUSTOM:
		return nil, fmt.Errorf("CUSTOM task type requires explicit check_type param")

	default:
		return nil, fmt.Errorf("unknown task type: %d", int(task.Type))
	}
}

// ─────────────────────────────────────────────
//  Handler: Host Discovery
// ─────────────────────────────────────────────

func (d *Dispatcher) handleHostDiscovery(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	subnet := task.Params["subnet"]
	if subnet == "" {
		// Auto-detect from local interfaces.
		subnets, err := scanner.AutoDetectSubnets()
		if err != nil || len(subnets) == 0 {
			return nil, fmt.Errorf("no subnet specified and auto-detect failed: %w", err)
		}
		subnet = subnets[0]
	}

	hosts, err := d.discovery.Scan(ctx, subnet)
	if err != nil {
		return nil, fmt.Errorf("host discovery on %s: %w", subnet, err)
	}

	findings := make([]*pb.Finding, 0, len(hosts))
	for _, h := range hosts {
		findings = append(findings, &pb.Finding{
			FindingId:   uuid.NewString(),
			TaskId:      task.TaskId,
			ScanId:      task.ScanId,
			Host:        h.Ip,
			Severity:    pb.Severity_INFO,
			Title:       "Live Host Discovered",
			Description: fmt.Sprintf("Host %s is alive (MAC: %s, Hostname: %s)", h.Ip, h.MacAddress, h.Hostname),
			Evidence:    fmt.Sprintf("ARP/ICMP response from %s", h.Ip),
			Metadata: map[string]string{
				"ip":       h.Ip,
				"mac":      h.MacAddress,
				"hostname": h.Hostname,
				"subnet":   subnet,
			},
			Timestamp: time.Now().UnixMilli(),
		})
	}
	return findings, nil
}

// ─────────────────────────────────────────────
//  Handler: Port Scan
// ─────────────────────────────────────────────

func (d *Dispatcher) handlePortScan(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		return nil, fmt.Errorf("port_scan requires param 'host'")
	}

	var ports []int
	if portList, ok := task.Params["ports"]; ok && portList != "" {
		for _, p := range strings.Split(portList, ",") {
			p = strings.TrimSpace(p)
			n, err := strconv.Atoi(p)
			if err != nil {
				continue
			}
			ports = append(ports, n)
		}
	}

	concurrency := 100
	if c, ok := task.Params["concurrency"]; ok {
		if n, err := strconv.Atoi(c); err == nil && n > 0 {
			concurrency = n
		}
	}

	openPorts, err := d.portScanner.WithConcurrency(concurrency).Scan(ctx, host, ports)
	if err != nil {
		return nil, fmt.Errorf("port scan %s: %w", host, err)
	}

	findings := make([]*pb.Finding, 0, len(openPorts))
	for _, p := range openPorts {
		findings = append(findings, &pb.Finding{
			FindingId:   uuid.NewString(),
			TaskId:      task.TaskId,
			ScanId:      task.ScanId,
			Host:        host,
			Port:        p.Number,
			Protocol:    p.Protocol,
			Service:     p.Service,
			Severity:    pb.Severity_INFO,
			Title:       fmt.Sprintf("Open Port: %d/%s (%s)", p.Number, p.Protocol, p.Service),
			Description: fmt.Sprintf("Port %d/%s is open on %s, service: %s", p.Number, p.Protocol, host, p.Service),
			Evidence:    fmt.Sprintf("TCP connect to %s:%d succeeded", host, p.Number),
			Metadata: map[string]string{
				"port":     strconv.Itoa(int(p.Number)),
				"protocol": p.Protocol,
				"service":  p.Service,
				"state":    p.State,
			},
			Timestamp: time.Now().UnixMilli(),
		})
	}
	return findings, nil
}

// ─────────────────────────────────────────────
//  Handler: Service Fingerprint
// ─────────────────────────────────────────────

func (d *Dispatcher) handleFingerprint(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		return nil, fmt.Errorf("service_fingerprint requires param 'host'")
	}
	portStr := task.Params["port"]
	if portStr == "" {
		return nil, fmt.Errorf("service_fingerprint requires param 'port'")
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	p := &pb.Port{
		Number:   int32(portNum),
		Protocol: "tcp",
		State:    "open",
		Service:  task.Params["service"],
	}

	enriched, err := d.fingerprint.Fingerprint(ctx, host, p)
	if err != nil {
		return nil, fmt.Errorf("fingerprint %s:%d: %w", host, portNum, err)
	}

	finding := &pb.Finding{
		FindingId:   uuid.NewString(),
		TaskId:      task.TaskId,
		ScanId:      task.ScanId,
		Host:        host,
		Port:        enriched.Number,
		Protocol:    enriched.Protocol,
		Service:     enriched.Service,
		Severity:    pb.Severity_INFO,
		Title:       fmt.Sprintf("Service Identified: %s on port %d", enriched.Service, enriched.Number),
		Description: fmt.Sprintf("Service fingerprinting identified %s (version: %s) on %s:%d", enriched.Service, enriched.Version, host, portNum),
		Evidence:    enriched.Banner,
		Metadata: map[string]string{
			"service": enriched.Service,
			"version": enriched.Version,
			"banner":  truncate(enriched.Banner, 500),
		},
		Timestamp: time.Now().UnixMilli(),
	}
	return []*pb.Finding{finding}, nil
}

// ─────────────────────────────────────────────
//  Handler: SMB Relay Check
// ─────────────────────────────────────────────

func (d *Dispatcher) handleSMBRelayCheck(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		return nil, fmt.Errorf("smb_relay_check requires param 'host'")
	}

	finding, err := d.smbChecker.Check(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("smb relay check %s: %w", host, err)
	}

	finding.TaskId = task.TaskId
	finding.ScanId = task.ScanId
	return []*pb.Finding{finding}, nil
}

// ─────────────────────────────────────────────
//  Handler: LLMNR Poisoning Check
// ─────────────────────────────────────────────

func (d *Dispatcher) handleLLMNRCheck(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	subnet := task.Params["subnet"]
	if subnet == "" {
		subnets, err := scanner.AutoDetectSubnets()
		if err != nil || len(subnets) == 0 {
			subnet = ""
		} else {
			subnet = subnets[0]
		}
	}

	finding, err := d.llmnrCheck.Check(ctx, subnet)
	if err != nil {
		return nil, fmt.Errorf("llmnr check on %s: %w", subnet, err)
	}

	finding.TaskId = task.TaskId
	finding.ScanId = task.ScanId
	return []*pb.Finding{finding}, nil
}

// ─────────────────────────────────────────────
//  Handler: Generic Vulnerability Check
// ─────────────────────────────────────────────

// handleVulnCheck acts as a meta-dispatcher: it routes VULN_CHECK tasks to
// specific sub-checks based on the "check_type" parameter.
func (d *Dispatcher) handleVulnCheck(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	checkType := task.Params["check_type"]
	switch strings.ToLower(checkType) {
	case "smb_relay", "smb-relay":
		return d.handleSMBRelayCheck(ctx, task)
	case "llmnr", "llmnr_poison", "llmnr-poison":
		return d.handleLLMNRCheck(ctx, task)
	default:
		return nil, fmt.Errorf("vuln_check: unknown check_type %q (supported: smb_relay, llmnr)", checkType)
	}
}

// ─────────────────────────────────────────────
//  Handler: Default Credential Test
// ─────────────────────────────────────────────

func (d *Dispatcher) handleDefaultCredTest(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		return nil, fmt.Errorf("default_cred_test requires param 'host'")
	}

	portStr := task.Params["port"]
	portNum := 0
	if portStr != "" {
		portNum, _ = strconv.Atoi(portStr)
	}

	service := task.Params["service"]
	if service == "" {
		if hint, ok := portServiceHints[portNum]; ok {
			service = hint
		}
	}

	finding, err := d.credChecker.Check(ctx, host, portNum, service)
	if err != nil {
		return nil, fmt.Errorf("cred check %s:%d: %w", host, portNum, err)
	}
	if finding != nil {
		finding.TaskId = task.TaskId
		finding.ScanId = task.ScanId
		return []*pb.Finding{finding}, nil
	}
	return nil, nil
}

// ─────────────────────────────────────────────
//  Handler: Active Directory Enumeration (incl. Kerberoast/AS-REP)
// ─────────────────────────────────────────────

func (d *Dispatcher) handleADEnum(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		return nil, fmt.Errorf("active_directory_enum requires param 'host'")
	}

	findings, err := d.adEnumerator.Enumerate(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("AD enumeration on %s: %w", host, err)
	}

	for _, f := range findings {
		f.TaskId = task.TaskId
		f.ScanId = task.ScanId
	}
	return findings, nil
}

// ─────────────────────────────────────────────
//  Handler: SSL/TLS Audit
// ─────────────────────────────────────────────

func (d *Dispatcher) handleSSLAudit(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		return nil, fmt.Errorf("ssl_tls_audit requires param 'host'")
	}
	portStr := task.Params["port"]
	if portStr == "" {
		portStr = "443"
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum <= 0 {
		portNum = 443
	}

	sslFindings, auditErr := d.sslAuditor.Audit(ctx, host, portNum)
	if auditErr != nil {
		return nil, fmt.Errorf("ssl audit %s:%d: %w", host, portNum, auditErr)
	}

	var findings []*pb.Finding
	for _, sf := range sslFindings {
		var sev pb.Severity
		switch sf.Severity {
		case 4:
			sev = pb.Severity_CRITICAL
		case 3:
			sev = pb.Severity_HIGH
		case 2:
			sev = pb.Severity_MEDIUM
		case 1:
			sev = pb.Severity_LOW
		default:
			sev = pb.Severity_INFO
		}

		meta := map[string]string{
			"port":    portStr,
			"service": "https",
		}
		if sf.CVEID != "" {
			meta["cve_id"] = sf.CVEID
		}

		findings = append(findings, &pb.Finding{
			FindingId:   uuid.NewString(),
			TaskId:      task.TaskId,
			ScanId:      task.ScanId,
			Host:        host,
			Port:        int32(portNum),
			Protocol:    "tcp",
			Service:     "https",
			Severity:    sev,
			CveId:       sf.CVEID,
			Title:       sf.Title,
			Description: sf.Description,
			Evidence:    sf.Evidence,
			Remediation: sf.Remediation,
			Metadata:    meta,
			Timestamp:   time.Now().UnixMilli(),
		})
	}
	return findings, nil
}

// ─────────────────────────────────────────────
//  Handler: HTTP Security Headers
// ─────────────────────────────────────────────

func (d *Dispatcher) handleHTTPHeaders(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		return nil, fmt.Errorf("http_security_headers requires param 'host'")
	}

	// If a specific port is requested, scan only that port; otherwise scan all web ports.
	if portStr, ok := task.Params["port"]; ok && portStr != "" {
		portNum, err := strconv.Atoi(portStr)
		if err != nil || portNum <= 0 {
			return nil, fmt.Errorf("invalid port %q", portStr)
		}
		findings, err := d.httpHeaders.Scan(ctx, host, portNum)
		if err != nil {
			return nil, fmt.Errorf("http headers scan %s:%d: %w", host, portNum, err)
		}
		for _, f := range findings {
			f.TaskId = task.TaskId
			f.ScanId = task.ScanId
		}
		return findings, nil
	}

	findings, err := d.httpHeaders.ScanHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("http headers scan %s: %w", host, err)
	}
	for _, f := range findings {
		f.TaskId = task.TaskId
		f.ScanId = task.ScanId
	}
	return findings, nil
}

// ─────────────────────────────────────────────
//  Handler: DNS Zone Transfer
// ─────────────────────────────────────────────

func (d *Dispatcher) handleDNSZoneTransfer(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		// Fall back to target param used by grpc_server.
		host = task.Params["target"]
	}
	if host == "" {
		return nil, fmt.Errorf("dns_zone_transfer requires param 'host'")
	}

	findings, err := d.dnsZoneXfer.Scan(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns zone transfer %s: %w", host, err)
	}
	for _, f := range findings {
		f.TaskId = task.TaskId
		f.ScanId = task.ScanId
	}
	return findings, nil
}

// ─────────────────────────────────────────────
//  Handler: Exposed Admin Panel
// ─────────────────────────────────────────────

func (d *Dispatcher) handleAdminPanel(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		return nil, fmt.Errorf("exposed_admin_panel requires param 'host'")
	}

	findings, err := d.adminPanel.Scan(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("admin panel scan %s: %w", host, err)
	}
	for _, f := range findings {
		f.TaskId = task.TaskId
		f.ScanId = task.ScanId
	}
	return findings, nil
}

// ─────────────────────────────────────────────
//  Handler: SNMP Community String
// ─────────────────────────────────────────────

func (d *Dispatcher) handleSNMP(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		return nil, fmt.Errorf("snmp_community_string requires param 'host'")
	}

	findings, err := d.snmpChecker.Check(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("snmp check %s: %w", host, err)
	}
	for _, f := range findings {
		f.TaskId = task.TaskId
		f.ScanId = task.ScanId
	}
	return findings, nil
}

// ─────────────────────────────────────────────
//  Handler: RDP Security Check
// ─────────────────────────────────────────────

func (d *Dispatcher) handleRDP(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		return nil, fmt.Errorf("rdp_security_check requires param 'host'")
	}

	findings, err := d.rdpChecker.Check(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("rdp security check %s: %w", host, err)
	}
	for _, f := range findings {
		f.TaskId = task.TaskId
		f.ScanId = task.ScanId
	}
	return findings, nil
}

// ─────────────────────────────────────────────
//  Handler: Web Application Scan
// ─────────────────────────────────────────────

func (d *Dispatcher) handleWebAppScan(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		host = task.Params["target"]
	}
	if host == "" {
		return nil, fmt.Errorf("web_app_scan requires param 'host'")
	}

	// Scan common web ports unless a specific port is given.
	webPorts := []int{80, 443, 8080, 8443}
	if portStr, ok := task.Params["port"]; ok && portStr != "" {
		var p int
		if _, err := fmt.Sscanf(portStr, "%d", &p); err == nil && p > 0 {
			webPorts = []int{p}
		}
	}

	var all []*pb.Finding
	for _, port := range webPorts {
		findings, err := d.webAppScanner.Scan(ctx, host, port)
		if err != nil {
			d.logger.Debug("web app scan skipped", "host", host, "port", port, "reason", err)
			continue
		}
		for _, f := range findings {
			f.TaskId = task.TaskId
			f.ScanId = task.ScanId
		}
		all = append(all, findings...)
	}
	return all, nil
}

// ─────────────────────────────────────────────
//  Handler: Nuclei Templated Scan
// ─────────────────────────────────────────────

// handleNucleiScan composes the URL to scan. The autonomous engine sends
// `host` + `port` separately (target=host, options.port=N), so we always
// prefer that pair when both are present. Only fall back to using `target`
// as a URL when it already includes a scheme — otherwise the bare host
// would be sent without its port and the scan would just hit port 80.
func (d *Dispatcher) handleNucleiScan(ctx context.Context, task *pb.ScanTask) ([]*pb.Finding, error) {
	host := task.Params["host"]
	if host == "" {
		host = strings.TrimSpace(task.Params["target"])
	}
	if host == "" {
		return nil, fmt.Errorf("nuclei_scan requires param 'host' or 'target'")
	}

	// If the caller already passed a fully-qualified URL, use it verbatim.
	if strings.Contains(host, "://") {
		url := host
		findings, err := d.nucleiScanner.Scan(ctx, url)
		if err != nil {
			return findings, fmt.Errorf("nuclei scan %s: %w", url, err)
		}
		for _, f := range findings {
			f.TaskId = task.TaskId
			f.ScanId = task.ScanId
		}
		return findings, nil
	}

	// Otherwise build the URL from host + port (+ scheme inferred from port).
	// Strip any "host:port" combo the caller may have included in `host`.
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	portStr := task.Params["port"]
	scheme := "http"
	portNum := 80
	if portStr != "" {
		n, err := strconv.Atoi(portStr)
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("nuclei_scan: invalid port %q", portStr)
		}
		portNum = n
		if portNum == 443 || portNum == 8443 {
			scheme = "https"
		}
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, host, portNum)

	findings, err := d.nucleiScanner.Scan(ctx, url)
	if err != nil {
		return findings, fmt.Errorf("nuclei scan %s: %w", url, err)
	}
	for _, f := range findings {
		f.TaskId = task.TaskId
		f.ScanId = task.ScanId
	}
	return findings, nil
}

// ─────────────────────────────────────────────
//  Utility
// ─────────────────────────────────────────────

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
