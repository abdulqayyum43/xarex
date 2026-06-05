// Package scanner — Exposed Admin Panel Module (task type 13)
//
// Probes common admin/management paths on web servers to identify exposed
// administrative interfaces. Exposed admin panels are prime targets for:
//
//   - Brute-force and credential stuffing attacks
//   - Exploitation of unpatched admin frameworks
//   - Direct system command execution (Tomcat manager, Jenkins, Actuator)
//   - Sensitive configuration / credential exposure (.env, config.php)
package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xarex/probe/grpc/pb"
)

// adminPath describes a path to probe and the severity of its exposure.
type adminPath struct {
	path        string
	severity    pb.Severity
	title       string
	description string
	remediation string
}

// AdminPanelScanner probes web servers for exposed administrative interfaces.
type AdminPanelScanner struct {
	logger      *slog.Logger
	timeout     time.Duration
	concurrency int
}

// NewAdminPanelScanner creates a new AdminPanelScanner.
func NewAdminPanelScanner(logger *slog.Logger) *AdminPanelScanner {
	return &AdminPanelScanner{
		logger:      logger,
		timeout:     5 * time.Second,
		concurrency: 10,
	}
}

// adminPorts are ports that will be probed for HTTP/HTTPS admin panels.
var adminPorts = []int{80, 443, 8080, 8443, 8888}

// adminPaths defines the full list of paths to probe with their severity mappings.
var adminPaths = []adminPath{
	// Critical — direct credential/configuration exposure
	{
		path:        "/.env",
		severity:    pb.Severity_CRITICAL,
		title:       "Exposed .env Configuration File",
		description: "The .env file is publicly accessible. This file typically contains database credentials, API keys, secret tokens, and other sensitive configuration values in plaintext. An attacker can harvest all application credentials from a single request.",
		remediation: "Immediately remove .env from the web root and block access via web server rules (e.g., 'location ~ /\\.env { deny all; }'). Rotate all exposed credentials.",
	},
	{
		path:        "/config.php",
		severity:    pb.Severity_CRITICAL,
		title:       "Exposed config.php Configuration File",
		description: "The application's config.php file is publicly accessible. PHP configuration files commonly contain database credentials, salts, and API keys in plaintext.",
		remediation: "Move configuration files outside the web root or block access with web server rules. Rotate any exposed credentials.",
	},
	// High — management interfaces with direct system access
	{
		path:        "/manager/html",
		severity:    pb.Severity_HIGH,
		title:       "Apache Tomcat Manager Interface Exposed",
		description: "The Apache Tomcat Manager web interface is exposed. This interface allows deployment of arbitrary WAR files, enabling Remote Code Execution if authentication can be bypassed or weak credentials are used.",
		remediation: "Restrict the Tomcat Manager to localhost only (server.xml: address=\"127.0.0.1\"). Remove the manager app if not needed. Enforce strong authentication.",
	},
	{
		path:        "/actuator/env",
		severity:    pb.Severity_HIGH,
		title:       "Spring Boot Actuator /env Endpoint Exposed",
		description: "The Spring Boot Actuator /env endpoint is exposed. This endpoint reveals all environment variables, configuration properties, and may include database passwords, API keys, and cloud provider credentials.",
		remediation: "Restrict actuator endpoints to management port: 'management.server.port=8081' and bind to localhost. Use 'management.endpoints.web.exposure.include' to whitelist only necessary endpoints.",
	},
	{
		path:        "/actuator",
		severity:    pb.Severity_HIGH,
		title:       "Spring Boot Actuator Endpoints Exposed",
		description: "Spring Boot Actuator endpoints are exposed without authentication. Actuator provides operational endpoints including /env, /health, /mappings, /beans, and potentially /shutdown, /jolokia (JMX).",
		remediation: "Secure all actuator endpoints with Spring Security. Restrict to an internal management port. Disable unused endpoints.",
	},
	{
		path:        "/wp-admin",
		severity:    pb.Severity_HIGH,
		title:       "WordPress Admin Panel Exposed",
		description: "The WordPress admin panel (/wp-admin) is publicly accessible. WordPress admin panels are frequent targets for brute-force attacks, credential stuffing, and plugin/theme exploitation.",
		remediation: "Restrict wp-admin access by IP. Enable two-factor authentication. Implement rate limiting for login attempts (fail2ban, WordPress security plugins).",
	},
	{
		path:        "/wp-login.php",
		severity:    pb.Severity_HIGH,
		title:       "WordPress Login Page Exposed",
		description: "The WordPress login page is publicly accessible. This is the primary target for automated brute-force attacks against WordPress installations.",
		remediation: "Implement login rate limiting, CAPTCHA, and two-factor authentication. Consider restricting wp-login.php access by source IP address.",
	},
	{
		path:        "/phpmyadmin",
		severity:    pb.Severity_HIGH,
		title:       "phpMyAdmin Interface Exposed",
		description: "The phpMyAdmin database management interface is publicly accessible. phpMyAdmin provides full database access and has a history of critical vulnerabilities including RCE (CVE-2018-12613, CVE-2016-5734).",
		remediation: "Restrict phpMyAdmin to localhost or specific admin IPs. Enable authentication. Update to the latest version. Consider removing entirely from production.",
	},
	{
		path:        "/pma",
		severity:    pb.Severity_HIGH,
		title:       "phpMyAdmin Interface Exposed (alternate path)",
		description: "A phpMyAdmin instance is accessible at /pma. Database management interfaces expose the entire database to attackers who bypass authentication.",
		remediation: "Restrict phpMyAdmin to localhost or internal IP ranges. Remove from production environments.",
	},
	{
		path:        "/adminer.php",
		severity:    pb.Severity_HIGH,
		title:       "Adminer Database Manager Exposed",
		description: "The Adminer database management tool is publicly accessible. Adminer supports multiple database backends and can be exploited for SSRF (CVE-2021-21311) and file read/write operations.",
		remediation: "Remove Adminer from production. If required, restrict access by IP and require authentication.",
	},
	{
		path:        "/jenkins",
		severity:    pb.Severity_HIGH,
		title:       "Jenkins CI/CD Server Exposed",
		description: "A Jenkins CI/CD server is accessible. Jenkins provides script console access (Groovy), build system access, and stored credentials. Unauthenticated or weakly-authenticated Jenkins has led to numerous supply chain attacks.",
		remediation: "Enable Jenkins authentication and authorization. Restrict network access to CI/CD infrastructure. Disable the script console for non-administrators.",
	},
	{
		path:        "/solr/admin",
		severity:    pb.Severity_HIGH,
		title:       "Apache Solr Admin Interface Exposed",
		description: "The Apache Solr admin interface is publicly accessible. Solr has multiple known critical vulnerabilities including SSRF, XXE, and RCE (CVE-2017-12629, CVE-2019-0193).",
		remediation: "Bind Solr to localhost only (jetty.host=127.0.0.1). Implement firewall rules to block external access. Update to the latest version.",
	},
	// Medium — login pages (credential targeting)
	{
		path:        "/admin",
		severity:    pb.Severity_MEDIUM,
		title:       "Admin Panel Login Exposed",
		description: "An administrative login panel is publicly accessible at /admin. This endpoint is a target for brute-force and credential stuffing attacks.",
		remediation: "Restrict admin login page access by source IP. Implement rate limiting and account lockout. Enable multi-factor authentication.",
	},
	{
		path:        "/administrator",
		severity:    pb.Severity_MEDIUM,
		title:       "Administrator Panel Login Exposed",
		description: "An administrator login panel is exposed at /administrator (common in Joomla CMS). Administrator panels are primary targets for authentication attacks.",
		remediation: "Restrict administrator URL by IP. Use a secret administrator path. Enable two-factor authentication and login rate limiting.",
	},
	{
		path:        "/admin/login",
		severity:    pb.Severity_MEDIUM,
		title:       "Admin Login Page Exposed",
		description: "An admin login page is publicly accessible. Authentication endpoints without rate limiting are vulnerable to brute-force attacks.",
		remediation: "Implement IP-based access control, CAPTCHA, and account lockout after failed attempts.",
	},
	{
		path:        "/user/login",
		severity:    pb.Severity_MEDIUM,
		title:       "User Login Page Exposed",
		description: "A user login page is exposed. Without rate limiting, this is susceptible to credential stuffing from breach databases.",
		remediation: "Implement rate limiting, CAPTCHA on repeated failures, and monitor for unusual login volumes.",
	},
	{
		path:        "/login",
		severity:    pb.Severity_MEDIUM,
		title:       "Login Page Exposed",
		description: "A login page is publicly accessible. This is a common target for automated credential attacks.",
		remediation: "Implement CAPTCHA, rate limiting, and multi-factor authentication.",
	},
	{
		path:        "/cpanel",
		severity:    pb.Severity_MEDIUM,
		title:       "cPanel Web Hosting Control Panel Exposed",
		description: "A cPanel hosting control panel login is accessible. cPanel provides server administration and is a high-value target for attackers.",
		remediation: "Restrict cPanel access to specific IP addresses. Enable two-factor authentication. Ensure cPanel is up to date.",
	},
	{
		path:        "/webmail",
		severity:    pb.Severity_MEDIUM,
		title:       "Webmail Interface Exposed",
		description: "A webmail interface is publicly accessible. Email accounts are high-value targets for credential attacks and business email compromise.",
		remediation: "Enable two-factor authentication. Implement rate limiting. Consider restricting to VPN access for corporate use.",
	},
	{
		path:        "/roundcube",
		severity:    pb.Severity_MEDIUM,
		title:       "Roundcube Webmail Exposed",
		description: "Roundcube webmail is accessible. Roundcube has had persistent XSS and RCE vulnerabilities (CVE-2020-12641, CVE-2023-5631).",
		remediation: "Keep Roundcube updated. Enable two-factor authentication. Restrict access by network if possible.",
	},
	{
		path:        "/mysql",
		severity:    pb.Severity_MEDIUM,
		title:       "MySQL Administration Interface Exposed",
		description: "A MySQL administration interface appears to be accessible via HTTP. Database admin tools should never be exposed to public networks.",
		remediation: "Remove web-based MySQL admin tools from production or restrict to localhost only.",
	},
	{
		path:        "/kibana",
		severity:    pb.Severity_MEDIUM,
		title:       "Kibana Dashboard Exposed",
		description: "A Kibana dashboard is publicly accessible. Kibana provides full access to Elasticsearch data and has known XSS and SSRF vulnerabilities.",
		remediation: "Require authentication (X-Pack security or reverse proxy). Restrict Kibana to internal network access only.",
	},
	{
		path:        "/grafana",
		severity:    pb.Severity_MEDIUM,
		title:       "Grafana Dashboard Exposed",
		description: "A Grafana monitoring dashboard is publicly accessible. Grafana has had critical authentication bypass vulnerabilities (CVE-2021-43798 — path traversal).",
		remediation: "Enable Grafana authentication. Update to a patched version. Restrict access by IP or VPN.",
	},
	{
		path:        "/actuator/health",
		severity:    pb.Severity_LOW,
		title:       "Spring Boot Actuator /health Exposed",
		description: "The Spring Boot Actuator /health endpoint is accessible. While less critical than /env, it may reveal infrastructure topology and internal service dependencies.",
		remediation: "Restrict actuator endpoints to an internal management port with authentication.",
	},
	// Low — information disclosure
	{
		path:        "/server-status",
		severity:    pb.Severity_LOW,
		title:       "Apache mod_status Server Status Exposed",
		description: "Apache's mod_status /server-status page is publicly accessible. This page exposes server version, active requests, client IP addresses, and request URIs — valuable reconnaissance for an attacker.",
		remediation: "Restrict /server-status to localhost: 'Require ip 127.0.0.1'. Disable mod_status in production.",
	},
	{
		path:        "/server-info",
		severity:    pb.Severity_LOW,
		title:       "Apache mod_info Server Info Exposed",
		description: "Apache's mod_info /server-info page is publicly accessible, exposing detailed server configuration including loaded modules, directives, and version information.",
		remediation: "Restrict /server-info to localhost or disable mod_info in production.",
	},
}

// Scan performs admin panel discovery against the specified host.
func (s *AdminPanelScanner) Scan(ctx context.Context, host string) ([]*pb.Finding, error) {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: s.timeout,
		MaxIdleConns:        s.concurrency,
	}
	client := &http.Client{
		Timeout:   s.timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type result struct {
		finding *pb.Finding
	}

	resultCh := make(chan result, len(adminPaths)*len(adminPorts))
	sem := make(chan struct{}, s.concurrency)

	var wg sync.WaitGroup
	for _, port := range adminPorts {
		for _, path := range adminPaths {
			port, path := port, path // capture
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				f := s.probePort(ctx, client, host, port, path)
				if f != nil {
					resultCh <- result{finding: f}
				}
			}()
		}
	}

	wg.Wait()
	close(resultCh)

	// Deduplicate findings by (path, severity) across ports — prefer highest severity port.
	type dedupKey struct {
		path string
	}
	seen := make(map[dedupKey]*pb.Finding)
	for r := range resultCh {
		key := dedupKey{path: r.finding.Metadata["path"]}
		if existing, ok := seen[key]; !ok || r.finding.Severity > existing.Severity {
			seen[key] = r.finding
		}
	}

	findings := make([]*pb.Finding, 0, len(seen))
	for _, f := range seen {
		findings = append(findings, f)
	}
	return findings, nil
}

// probePort checks a single path on a specific host:port combination.
// Returns a Finding if the path is exposed (HTTP 200, 401, or 403), nil otherwise.
func (s *AdminPanelScanner) probePort(
	ctx context.Context,
	client *http.Client,
	host string,
	port int,
	path adminPath,
) *pb.Finding {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path.path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "XarexProbe/1.0 Security Scanner")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close() //nolint:errcheck

	// Only flag responses that indicate the resource exists.
	// 404/410/500 = not present. 200/401/403 = exposed (even if requires auth).
	switch resp.StatusCode {
	case http.StatusOK,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		// These all indicate the path exists on the server.
	default:
		return nil
	}

	// Collect first 512 bytes of response body for evidence.
	bodyBuf := make([]byte, 512)
	n, _ := resp.Body.Read(bodyBuf)
	bodyPreview := strings.TrimSpace(string(bodyBuf[:n]))
	if len(bodyPreview) > 256 {
		bodyPreview = bodyPreview[:256] + "…"
	}

	evidence := fmt.Sprintf(
		"URL: %s\nHTTP Status: %d %s\nContent-Type: %s\nServer: %s\n\nBody preview:\n%s",
		url,
		resp.StatusCode,
		resp.Status,
		resp.Header.Get("Content-Type"),
		resp.Header.Get("Server"),
		bodyPreview,
	)

	s.logger.Info("admin panel found",
		"host", host, "port", port, "path", path.path, "status", resp.StatusCode)

	return &pb.Finding{
		FindingId:   uuid.NewString(),
		Host:        host,
		Port:        int32(port),
		Protocol:    "tcp",
		Service:     scheme,
		Severity:    path.severity,
		Title:       path.title,
		Description: path.description,
		Evidence:    evidence,
		Remediation: path.remediation,
		Metadata: map[string]string{
			"path":        path.path,
			"url":         url,
			"status_code": fmt.Sprintf("%d", resp.StatusCode),
			"port":        fmt.Sprintf("%d", port),
			"scheme":      scheme,
		},
		Timestamp: time.Now().UnixMilli(),
	}
}
