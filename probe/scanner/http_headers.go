// Package scanner — HTTP Security Headers Module (task type 11)
//
// Checks web servers for missing or misconfigured HTTP security headers that
// leave applications vulnerable to common web attacks:
//
//   - Strict-Transport-Security (HSTS)         → SSL stripping / MitM
//   - Content-Security-Policy                  → XSS / data injection
//   - X-Frame-Options                          → Clickjacking
//   - X-Content-Type-Options                   → MIME-type sniffing
//   - Referrer-Policy                          → Sensitive URL leakage
//   - Permissions-Policy                       → Feature/API exposure
//   - X-XSS-Protection                        → Legacy XSS filter hint
package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xarex/probe/grpc/pb"
)

// headerCheck describes a single security header check.
type headerCheck struct {
	name        string
	validate    func(value string, scheme string) (sev pb.Severity, detail string)
	missingOnly bool // if true, only flag when header is absent entirely
}

// HTTPHeaderScanner checks web servers for missing/misconfigured HTTP security headers.
type HTTPHeaderScanner struct {
	logger  *slog.Logger
	timeout time.Duration
}

// NewHTTPHeaderScanner creates a new HTTPHeaderScanner.
func NewHTTPHeaderScanner(logger *slog.Logger) *HTTPHeaderScanner {
	return &HTTPHeaderScanner{
		logger:  logger,
		timeout: 8 * time.Second,
	}
}

// webPorts are the ports that will be probed for HTTP/HTTPS.
var webPorts = []int{80, 443, 8080, 8443}

// Scan checks all common web ports on host for missing/misconfigured security headers.
func (s *HTTPHeaderScanner) Scan(ctx context.Context, host string, port int) ([]*pb.Finding, error) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	target := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // pentest scanner — intentional
		},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: s.timeout,
	}
	client := &http.Client{
		Timeout:   s.timeout,
		Transport: transport,
		// Do not follow redirects — we want the initial response headers.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", target, err)
	}
	req.Header.Set("User-Agent", "XarexProbe/1.0 Security Scanner")

	resp, err := client.Do(req)
	if err != nil {
		// Not an error — host may not have a web server on this port.
		s.logger.Debug("http_headers: no web server", "host", host, "port", port, "error", err)
		return nil, nil //nolint:nilerr // expected: port may not serve HTTP
	}
	defer resp.Body.Close() //nolint:errcheck

	// Collect all response headers for evidence.
	var headerDump strings.Builder
	headerDump.WriteString(fmt.Sprintf("HTTP/%s %d %s\n", resp.Proto, resp.StatusCode, resp.Status))
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&headerDump, "%s: %s\n", k, v)
		}
	}
	evidence := headerDump.String()

	s.logger.Debug("http_headers: got response",
		"host", host, "port", port, "status", resp.StatusCode)

	var findings []*pb.Finding

	checks := s.buildChecks()
	for _, chk := range checks {
		value := resp.Header.Get(chk.name)
		if value == "" && chk.missingOnly {
			// Header is absent — determine severity.
			sev, detail := chk.validate("", scheme)
			if sev > pb.Severity_INFO {
				findings = append(findings, s.makeFinding(
					host, port, scheme, chk.name, sev,
					fmt.Sprintf("Missing security header: %s", chk.name),
					detail, evidence, resp,
				))
			}
			continue
		}
		if value == "" {
			sev, detail := chk.validate("", scheme)
			if sev > pb.Severity_INFO {
				findings = append(findings, s.makeFinding(
					host, port, scheme, chk.name, sev,
					fmt.Sprintf("Missing security header: %s", chk.name),
					detail, evidence, resp,
				))
			}
			continue
		}
		// Header present — validate its value.
		if sev, detail := chk.validate(value, scheme); sev > pb.Severity_INFO {
			findings = append(findings, s.makeFinding(
				host, port, scheme, chk.name, sev,
				fmt.Sprintf("Misconfigured security header: %s", chk.name),
				detail, evidence, resp,
			))
		}
	}

	return findings, nil
}

// ScanHost is a convenience wrapper that probes all well-known web ports.
func (s *HTTPHeaderScanner) ScanHost(ctx context.Context, host string) ([]*pb.Finding, error) {
	var all []*pb.Finding
	for _, port := range webPorts {
		findings, err := s.Scan(ctx, host, port)
		if err != nil {
			s.logger.Warn("http_headers scan error", "host", host, "port", port, "error", err)
			continue
		}
		all = append(all, findings...)
	}
	return all, nil
}

// buildChecks returns all header checks to perform.
func (s *HTTPHeaderScanner) buildChecks() []headerCheck {
	return []headerCheck{
		{
			name: "Strict-Transport-Security",
			validate: func(value, scheme string) (pb.Severity, string) {
				if scheme != "https" {
					return pb.Severity_INFO, ""
				}
				if value == "" {
					return pb.Severity_HIGH, "HSTS header absent on HTTPS endpoint. " +
						"An attacker can perform SSL stripping to downgrade connections to HTTP, " +
						"enabling credential theft. Remediation: Add " +
						"'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
				}
				lower := strings.ToLower(value)
				// Check max-age ≥ 1 year
				if !strings.Contains(lower, "max-age=") {
					return pb.Severity_HIGH, fmt.Sprintf(
						"HSTS header present but missing max-age directive (value: %q). "+
							"Without max-age the HSTS policy is invalid.", value)
				}
				var maxAge int
				fmt.Sscanf(strings.ToLower(value), "max-age=%d", &maxAge) //nolint:errcheck
				if maxAge < 31536000 {
					return pb.Severity_MEDIUM, fmt.Sprintf(
						"HSTS max-age=%d is too short (minimum recommended: 31536000 = 1 year). "+
							"Short HSTS windows allow SSL-stripping after expiry.", maxAge)
				}
				return pb.Severity_INFO, ""
			},
		},
		{
			name: "Content-Security-Policy",
			validate: func(value, scheme string) (pb.Severity, string) {
				if value == "" {
					return pb.Severity_MEDIUM, "Content-Security-Policy header is absent. " +
						"Without CSP, browsers permit inline scripts and unrestricted resource loading, " +
						"making the application susceptible to XSS and data injection attacks. " +
						"Remediation: Implement a restrictive CSP e.g. " +
						"'default-src \\'self\\'; script-src \\'self\\'; object-src \\'none\\''."
				}
				lower := strings.ToLower(value)
				if strings.Contains(lower, "unsafe-inline") && strings.Contains(lower, "script-src") {
					return pb.Severity_MEDIUM, fmt.Sprintf(
						"CSP allows 'unsafe-inline' scripts (value: %q). "+
							"This negates XSS protection by permitting inline script execution.", value)
				}
				if strings.Contains(lower, "unsafe-eval") {
					return pb.Severity_LOW, fmt.Sprintf(
						"CSP allows 'unsafe-eval' (value: %q). "+
							"eval() usage opens the door to script injection via dynamic evaluation.", value)
				}
				if strings.Contains(lower, "*") {
					return pb.Severity_MEDIUM, fmt.Sprintf(
						"CSP contains wildcard source '*' (value: %q). "+
							"Wildcard allows loading resources from any origin, undermining CSP.", value)
				}
				return pb.Severity_INFO, ""
			},
		},
		{
			name: "X-Frame-Options",
			validate: func(value, scheme string) (pb.Severity, string) {
				if value == "" {
					return pb.Severity_MEDIUM, "X-Frame-Options header is absent. " +
						"The application can be embedded in an iframe, enabling clickjacking attacks " +
						"where users are tricked into clicking UI elements they cannot see. " +
						"Remediation: Add 'X-Frame-Options: DENY' or use CSP frame-ancestors."
				}
				upper := strings.ToUpper(value)
				if upper != "DENY" && upper != "SAMEORIGIN" && !strings.HasPrefix(upper, "ALLOW-FROM") {
					return pb.Severity_LOW, fmt.Sprintf(
						"X-Frame-Options has unrecognised value %q. "+
							"Browsers may ignore invalid values, leaving clickjacking protections disabled.", value)
				}
				return pb.Severity_INFO, ""
			},
		},
		{
			name: "X-Content-Type-Options",
			validate: func(value, scheme string) (pb.Severity, string) {
				if value == "" {
					return pb.Severity_LOW, "X-Content-Type-Options header is absent. " +
						"Browsers may MIME-sniff responses, allowing attackers to serve malicious content " +
						"(e.g., an HTML file disguised as an image) that executes in the browser context. " +
						"Remediation: Add 'X-Content-Type-Options: nosniff'."
				}
				if !strings.EqualFold(strings.TrimSpace(value), "nosniff") {
					return pb.Severity_LOW, fmt.Sprintf(
						"X-Content-Type-Options has unexpected value %q; expected 'nosniff'.", value)
				}
				return pb.Severity_INFO, ""
			},
		},
		{
			name: "Referrer-Policy",
			validate: func(value, scheme string) (pb.Severity, string) {
				if value == "" {
					return pb.Severity_LOW, "Referrer-Policy header is absent. " +
						"The browser's default referrer behaviour may leak sensitive URL parameters " +
						"(e.g., session tokens, search queries) to third-party sites via the Referer header. " +
						"Remediation: Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."
				}
				unsafe := []string{"unsafe-url", "no-referrer-when-downgrade"}
				lower := strings.ToLower(strings.TrimSpace(value))
				for _, u := range unsafe {
					if lower == u {
						return pb.Severity_LOW, fmt.Sprintf(
							"Referrer-Policy is set to '%s' which leaks full URL paths to external origins. "+
								"Prefer 'strict-origin-when-cross-origin' or 'no-referrer'.", value)
					}
				}
				return pb.Severity_INFO, ""
			},
		},
		{
			name: "Permissions-Policy",
			validate: func(value, scheme string) (pb.Severity, string) {
				if value == "" {
					return pb.Severity_LOW, "Permissions-Policy (formerly Feature-Policy) header is absent. " +
						"Without this header, the browser grants default access to sensitive APIs " +
						"(camera, microphone, geolocation) that could be abused by injected third-party scripts. " +
						"Remediation: Add 'Permissions-Policy: geolocation=(), camera=(), microphone=()'."
				}
				return pb.Severity_INFO, ""
			},
		},
		{
			name: "X-XSS-Protection",
			validate: func(value, scheme string) (pb.Severity, string) {
				if value == "" {
					return pb.Severity_LOW, "X-XSS-Protection header is absent. " +
						"While deprecated in modern browsers and superseded by CSP, its absence on legacy " +
						"browsers (IE/older Chrome/Safari) leaves reflected XSS protections disabled. " +
						"Remediation: Add 'X-XSS-Protection: 1; mode=block' for defence-in-depth."
				}
				if strings.HasPrefix(strings.TrimSpace(value), "0") {
					return pb.Severity_LOW, fmt.Sprintf(
						"X-XSS-Protection is explicitly disabled (value: %q). "+
							"This turns off the browser's built-in XSS auditor on older browsers.", value)
				}
				return pb.Severity_INFO, ""
			},
		},
	}
}

func (s *HTTPHeaderScanner) makeFinding(
	host string,
	port int,
	scheme string,
	header string,
	sev pb.Severity,
	title string,
	description string,
	evidence string,
	resp *http.Response,
) *pb.Finding {
	return &pb.Finding{
		FindingId:   uuid.NewString(),
		Host:        host,
		Port:        int32(port),
		Protocol:    "tcp",
		Service:     scheme,
		Severity:    sev,
		Title:       title,
		Description: description,
		Evidence: fmt.Sprintf("URL: %s %d\nMissing/misconfigured header: %s\n\n--- Response Headers ---\n%s",
			resp.Request.URL.String(), resp.StatusCode, header, evidence),
		Remediation: s.remediation(header),
		Metadata: map[string]string{
			"header": header,
			"port":   fmt.Sprintf("%d", port),
			"scheme": scheme,
			"url":    resp.Request.URL.String(),
		},
		Timestamp: time.Now().UnixMilli(),
	}
}

func (s *HTTPHeaderScanner) remediation(header string) string {
	remediations := map[string]string{
		"Strict-Transport-Security": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
		"Content-Security-Policy":   "Define a restrictive Content-Security-Policy. Start with 'default-src \\'self\\'' and add specific source allowlists.",
		"X-Frame-Options":           "Add 'X-Frame-Options: DENY' or migrate to CSP 'frame-ancestors \\'none\\''.",
		"X-Content-Type-Options":    "Add 'X-Content-Type-Options: nosniff' to all responses.",
		"Referrer-Policy":           "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
		"Permissions-Policy":        "Add 'Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()' to restrict browser feature access.",
		"X-XSS-Protection":          "Add 'X-XSS-Protection: 1; mode=block'. Prefer implementing a strong CSP as primary XSS mitigation.",
	}
	if r, ok := remediations[header]; ok {
		return r
	}
	return fmt.Sprintf("Review and configure the %s header according to OWASP Secure Headers Project guidelines.", header)
}
