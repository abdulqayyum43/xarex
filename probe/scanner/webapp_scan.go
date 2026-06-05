// Package scanner — Web Application Security Scanner
// Checks for OWASP Top 10 vulnerabilities: SQLi, XSS, open redirects,
// sensitive file exposure, directory traversal, and missing security controls.
package scanner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xarex/probe/grpc/pb"
)

// WebAppScanner performs OWASP Top 10 checks against a web target.
type WebAppScanner struct {
	logger *slog.Logger
	client *http.Client
}

func NewWebAppScanner(logger *slog.Logger) *WebAppScanner {
	return &WebAppScanner{
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects — we test them
			},
		},
	}
}

// Scan runs all web app checks against the target host and returns findings.
func (w *WebAppScanner) Scan(ctx context.Context, host string, port int) ([]*pb.Finding, error) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, port)

	// Quick reachability check
	resp, err := w.get(ctx, baseURL+"/")
	if err != nil {
		return nil, fmt.Errorf("web app scan: target %s unreachable: %w", baseURL, err)
	}
	resp.Body.Close()

	var findings []*pb.Finding

	checks := []func(context.Context, string) ([]*pb.Finding, error){
		w.checkSensitiveFiles,
		w.checkSQLInjection,
		w.checkXSS,
		w.checkOpenRedirect,
		w.checkDirectoryTraversal,
		w.checkSecurityMisconfiguration,
	}

	for _, check := range checks {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		ff, err := check(ctx, baseURL)
		if err != nil {
			w.logger.Warn("web app check error", "url", baseURL, "error", err)
			continue
		}
		findings = append(findings, ff...)
	}

	return findings, nil
}

// ─── Sensitive File Exposure ─────────────────────────────────────────────────

var sensitiveFiles = []struct {
	path     string
	desc     string
	severity pb.Severity
}{
	{"/.env", "Environment file (credentials/API keys)", pb.Severity_CRITICAL},
	{"/.git/config", "Git repository config exposed", pb.Severity_HIGH},
	{"/.git/HEAD", "Git HEAD exposed (source code leak)", pb.Severity_HIGH},
	{"/backup.zip", "Backup archive exposed", pb.Severity_HIGH},
	{"/backup.sql", "Database backup exposed", pb.Severity_CRITICAL},
	{"/db.sql", "Database dump exposed", pb.Severity_CRITICAL},
	{"/config.php", "PHP config file exposed", pb.Severity_HIGH},
	{"/wp-config.php", "WordPress config exposed", pb.Severity_CRITICAL},
	{"/phpinfo.php", "PHP info page exposed", pb.Severity_MEDIUM},
	{"/.htpasswd", "htpasswd credentials exposed", pb.Severity_HIGH},
	{"/server-status", "Apache server-status exposed", pb.Severity_MEDIUM},
	{"/actuator/env", "Spring Boot env actuator exposed", pb.Severity_HIGH},
	{"/actuator/health", "Spring Boot health actuator exposed", pb.Severity_LOW},
	{"/api/swagger.json", "API Swagger spec exposed", pb.Severity_LOW},
	{"/swagger-ui.html", "Swagger UI exposed", pb.Severity_LOW},
	{"/.DS_Store", "macOS .DS_Store exposed (directory listing leak)", pb.Severity_LOW},
}

func (w *WebAppScanner) checkSensitiveFiles(ctx context.Context, baseURL string) ([]*pb.Finding, error) {
	var findings []*pb.Finding
	for _, sf := range sensitiveFiles {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		target := baseURL + sf.path
		resp, err := w.get(ctx, target)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()

		if resp.StatusCode == 200 {
			findings = append(findings, &pb.Finding{
				FindingId:   uuid.NewString(),
				Host:        extractHost(baseURL),
				Port:        int32(extractPort(baseURL)),
				Protocol:    "tcp",
				Service:     "http",
				Severity:    sf.severity,
				Title:       fmt.Sprintf("Sensitive File Exposed: %s", sf.path),
				Description: sf.desc + fmt.Sprintf(" at %s", target),
				Evidence:    fmt.Sprintf("HTTP %d — %s", resp.StatusCode, truncate(string(body), 200)),
				Remediation: "Restrict access to sensitive files via web server configuration. Remove backup files and disable directory browsing.",
				Metadata:    map[string]string{"url": target, "status_code": fmt.Sprintf("%d", resp.StatusCode)},
				Timestamp:   time.Now().UnixMilli(),
			})
		}
	}
	return findings, nil
}

// ─── SQL Injection ───────────────────────────────────────────────────────────

var sqliPayloads = []string{`'`, `"`, `' OR '1'='1`, `1; DROP TABLE users--`, `' UNION SELECT NULL--`}
var sqliErrors = []string{
	"syntax error", "mysql_fetch", "ORA-", "Microsoft OLE DB",
	"SQLSTATE", "pg_query()", "sqlite3_", "unclosed quotation",
	"you have an error in your sql syntax",
}

func (w *WebAppScanner) checkSQLInjection(ctx context.Context, baseURL string) ([]*pb.Finding, error) {
	testPaths := []string{"/search?q=", "/login?user=", "/product?id=", "/?id=", "/item?id="}
	for _, path := range testPaths {
		for _, payload := range sqliPayloads {
			select {
			case <-ctx.Done():
				return nil, nil
			default:
			}
			target := baseURL + path + url.QueryEscape(payload)
			resp, err := w.get(ctx, target)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()
			bodyLower := strings.ToLower(string(body))
			for _, errStr := range sqliErrors {
				if strings.Contains(bodyLower, errStr) {
					return []*pb.Finding{{
						FindingId:   uuid.NewString(),
						Host:        extractHost(baseURL),
						Port:        int32(extractPort(baseURL)),
						Protocol:    "tcp",
						Service:     "http",
						Severity:    pb.Severity_CRITICAL,
						Title:       "SQL Injection Vulnerability Detected",
						Description: fmt.Sprintf("Error-based SQL injection found at %s with payload: %s", path, payload),
						Evidence:    fmt.Sprintf("DB error in response: '%s' — URL: %s", errStr, target),
						Remediation: "Use parameterised queries / prepared statements. Never concatenate user input into SQL strings.",
						Metadata:    map[string]string{"url": target, "payload": payload, "error_indicator": errStr},
						Timestamp:   time.Now().UnixMilli(),
					}}, nil
				}
			}
		}
	}
	return nil, nil
}

// ─── Reflected XSS ──────────────────────────────────────────────────────────

var xssPayloads = []string{
	`<script>alert(1)</script>`,
	`"><script>alert(1)</script>`,
	`'><img src=x onerror=alert(1)>`,
}

func (w *WebAppScanner) checkXSS(ctx context.Context, baseURL string) ([]*pb.Finding, error) {
	testPaths := []string{"/search?q=", "/?q=", "/page?name="}
	for _, path := range testPaths {
		for _, payload := range xssPayloads {
			select {
			case <-ctx.Done():
				return nil, nil
			default:
			}
			target := baseURL + path + url.QueryEscape(payload)
			resp, err := w.get(ctx, target)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			// Check if payload is reflected unencoded
			if strings.Contains(string(body), payload) {
				return []*pb.Finding{{
					FindingId:   uuid.NewString(),
					Host:        extractHost(baseURL),
					Port:        int32(extractPort(baseURL)),
					Protocol:    "tcp",
					Service:     "http",
					Severity:    pb.Severity_HIGH,
					Title:       "Reflected Cross-Site Scripting (XSS)",
					Description: fmt.Sprintf("User input is reflected in the response without encoding at %s", path),
					Evidence:    fmt.Sprintf("Payload reflected verbatim — URL: %s", target),
					Remediation: "HTML-encode all user-controlled output. Implement a strict Content-Security-Policy header.",
					Metadata:    map[string]string{"url": target, "payload": payload},
					Timestamp:   time.Now().UnixMilli(),
				}}, nil
			}
		}
	}
	return nil, nil
}

// ─── Open Redirect ───────────────────────────────────────────────────────────

func (w *WebAppScanner) checkOpenRedirect(ctx context.Context, baseURL string) ([]*pb.Finding, error) {
	testPaths := []string{
		"/redirect?url=https://evil.com",
		"/login?next=https://evil.com",
		"/?return=https://evil.com",
		"/out?link=https://evil.com",
	}
	for _, path := range testPaths {
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}
		resp, err := w.get(ctx, baseURL+path)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if strings.Contains(loc, "evil.com") {
				return []*pb.Finding{{
					FindingId:   uuid.NewString(),
					Host:        extractHost(baseURL),
					Port:        int32(extractPort(baseURL)),
					Protocol:    "tcp",
					Service:     "http",
					Severity:    pb.Severity_MEDIUM,
					Title:       "Open Redirect Vulnerability",
					Description: fmt.Sprintf("Application redirects to attacker-controlled URL at %s", path),
					Evidence:    fmt.Sprintf("HTTP %d → Location: %s", resp.StatusCode, loc),
					Remediation: "Validate and whitelist redirect destinations. Never use raw user input in redirect URLs.",
					Metadata:    map[string]string{"url": baseURL + path, "location": loc},
					Timestamp:   time.Now().UnixMilli(),
				}}, nil
			}
		}
	}
	return nil, nil
}

// ─── Directory Traversal ─────────────────────────────────────────────────────

var traversalPayloads = []string{
	"../../../../etc/passwd",
	"..%2F..%2F..%2Fetc%2Fpasswd",
	"....//....//etc/passwd",
}

func (w *WebAppScanner) checkDirectoryTraversal(ctx context.Context, baseURL string) ([]*pb.Finding, error) {
	testPaths := []string{"/file?name=", "/download?path=", "/read?file=", "/?page="}
	for _, path := range testPaths {
		for _, payload := range traversalPayloads {
			select {
			case <-ctx.Done():
				return nil, nil
			default:
			}
			target := baseURL + path + payload
			resp, err := w.get(ctx, target)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			if strings.Contains(string(body), "root:x:") || strings.Contains(string(body), "root:!:") {
				return []*pb.Finding{{
					FindingId:   uuid.NewString(),
					Host:        extractHost(baseURL),
					Port:        int32(extractPort(baseURL)),
					Protocol:    "tcp",
					Service:     "http",
					Severity:    pb.Severity_CRITICAL,
					Title:       "Directory Traversal / Path Traversal",
					Description: fmt.Sprintf("File traversal allows reading /etc/passwd via %s", path),
					Evidence:    fmt.Sprintf("Response contains /etc/passwd content — URL: %s", target),
					Remediation: "Canonicalise and validate all file paths. Use a chroot or sandbox. Never resolve user-supplied paths against the filesystem.",
					Metadata:    map[string]string{"url": target, "payload": payload},
					Timestamp:   time.Now().UnixMilli(),
				}}, nil
			}
		}
	}
	return nil, nil
}

// ─── Security Misconfiguration ───────────────────────────────────────────────

func (w *WebAppScanner) checkSecurityMisconfiguration(ctx context.Context, baseURL string) ([]*pb.Finding, error) {
	var findings []*pb.Finding

	// Debug/stack trace endpoints
	debugPaths := []string{"/debug", "/trace", "/console", "/error", "/_debug", "/health/details"}
	for _, path := range debugPaths {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		resp, err := w.get(ctx, baseURL+path)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		bodyLower := strings.ToLower(string(body))
		if resp.StatusCode == 200 && (strings.Contains(bodyLower, "stack trace") ||
			strings.Contains(bodyLower, "exception") ||
			strings.Contains(bodyLower, "debug") ||
			strings.Contains(bodyLower, "traceback")) {
			findings = append(findings, &pb.Finding{
				FindingId:   uuid.NewString(),
				Host:        extractHost(baseURL),
				Port:        int32(extractPort(baseURL)),
				Protocol:    "tcp",
				Service:     "http",
				Severity:    pb.Severity_MEDIUM,
				Title:       "Debug Information Exposed",
				Description: fmt.Sprintf("Debug endpoint %s exposes stack traces or internal error details", path),
				Evidence:    fmt.Sprintf("HTTP %d with debug content at %s%s", resp.StatusCode, baseURL, path),
				Remediation: "Disable debug endpoints in production. Return generic error messages to clients.",
				Metadata:    map[string]string{"url": baseURL + path},
				Timestamp:   time.Now().UnixMilli(),
			})
		}
	}

	// HTTP methods check (TRACE enabled)
	req, err := http.NewRequestWithContext(ctx, "TRACE", baseURL+"/", nil)
	if err == nil {
		resp, err := w.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				findings = append(findings, &pb.Finding{
					FindingId:   uuid.NewString(),
					Host:        extractHost(baseURL),
					Port:        int32(extractPort(baseURL)),
					Protocol:    "tcp",
					Service:     "http",
					Severity:    pb.Severity_LOW,
					Title:       "HTTP TRACE Method Enabled",
					Description: "TRACE method is enabled which can be exploited for Cross-Site Tracing (XST) attacks",
					Evidence:    "HTTP TRACE request returned 200 OK",
					Remediation: "Disable TRACE method in web server configuration.",
					Metadata:    map[string]string{"method": "TRACE"},
					Timestamp:   time.Now().UnixMilli(),
				})
			}
		}
	}

	return findings, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (w *WebAppScanner) get(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Xarex-Security-Scanner/1.0")
	return w.client.Do(req)
}

func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

func extractPort(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 80
	}
	switch u.Port() {
	case "443", "8443":
		return 443
	case "8080":
		return 8080
	case "":
		if u.Scheme == "https" {
			return 443
		}
		return 80
	default:
		var p int
		fmt.Sscanf(u.Port(), "%d", &p)
		return p
	}
}
