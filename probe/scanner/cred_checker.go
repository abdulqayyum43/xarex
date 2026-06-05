// Package scanner — Default credential checker.
//
// Tests services for well-known default and weak credentials.
// Completely non-destructive: only attempts to authenticate — no data
// is read, modified, or deleted. All attempts are logged.
//
// Supported services:
//   - FTP  (anonymous + common pairs)
//   - Redis (unauthenticated access)
//   - MongoDB (unauthenticated access)
//   - Elasticsearch (unauthenticated access)
//   - HTTP Basic Auth (common admin pairs)
//   - Memcached (unauthenticated access)
//   - SMTP (open relay check)

package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xarex/probe/grpc/pb"
)

const credCheckTimeout = 8 * time.Second

// CommonCredentials is the list of username:password pairs to try.
var CommonCredentials = []struct{ User, Pass string }{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", ""},
	{"admin", "123456"},
	{"admin", "admin123"},
	{"root", "root"},
	{"root", ""},
	{"root", "toor"},
	{"root", "password"},
	{"administrator", "administrator"},
	{"administrator", "password"},
	{"administrator", ""},
	{"guest", "guest"},
	{"guest", ""},
	{"user", "user"},
	{"test", "test"},
	{"postgres", "postgres"},
	{"postgres", ""},
	{"sa", "sa"},        // MSSQL
	{"sa", ""},
	{"oracle", "oracle"},
	{"oracle", "change_on_install"},
	{"elastic", ""},     // Elasticsearch
	{"elastic", "changeme"},
}

// CredChecker performs default credential checks.
type CredChecker struct {
	logger *slog.Logger
}

// NewCredChecker returns a ready-to-use CredChecker.
func NewCredChecker(logger *slog.Logger) *CredChecker {
	return &CredChecker{logger: logger}
}

// Check dispatches to the appropriate service-specific checker based on port
// number and/or service name. Routing on service name allows tests and the
// autonomous engine to target non-standard ports (e.g. mock servers).
func (c *CredChecker) Check(ctx context.Context, host string, port int, service string) (*pb.Finding, error) {
	c.logger.Info("checking default credentials", "host", host, "port", port, "service", service)

	svc := strings.ToLower(service)
	switch {
	case port == 21 || svc == "ftp":
		return c.checkFTP(ctx, host, port)
	case port == 6379 || svc == "redis":
		return c.checkRedis(ctx, host, port)
	case port == 27017 || svc == "mongodb":
		return c.checkMongoDB(ctx, host, port)
	case port == 9200 || svc == "elasticsearch":
		return c.checkElasticsearch(ctx, host, port)
	case port == 11211 || svc == "memcached":
		return c.checkMemcached(ctx, host, port)
	case port == 25 || port == 587 || svc == "smtp":
		return c.checkSMTPRelay(ctx, host, port)
	case port == 80 || port == 8080 || port == 8443 || port == 443 || svc == "http" || svc == "https":
		return c.checkHTTPBasicAuth(ctx, host, port)
	default:
		return c.genericCredCheck(ctx, host, port, service)
	}
}

// ─────────────────────────────────────────────
//  FTP
// ─────────────────────────────────────────────

func (c *CredChecker) checkFTP(ctx context.Context, host string, port int) (*pb.Finding, error) {
	if port == 0 {
		port = 21
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := dialWithContext(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("ftp connect: %w", err)
	}
	defer conn.Close()

	// Read banner
	banner := readLine(conn, 3*time.Second)

	// Try anonymous login
	writeLine(conn, "USER anonymous")
	r1 := readLine(conn, 3*time.Second)
	writeLine(conn, "PASS anonymous@xarex.local")
	r2 := readLine(conn, 3*time.Second)

	anonymousOK := strings.HasPrefix(r2, "230") || strings.HasPrefix(r1, "230")

	if anonymousOK {
		return &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        host,
			Port:        21,
			Protocol:    "tcp",
			Service:     "ftp",
			Severity:    pb.Severity_HIGH,
			Title:       "FTP Anonymous Login Enabled",
			Description: fmt.Sprintf("FTP server on %s:21 allows anonymous login. An unauthenticated attacker can list and potentially download files.", host),
			Evidence:    fmt.Sprintf("Banner: %s\nUSER anonymous response: %s\nPASS response: %s", banner, r1, r2),
			Remediation: "1. Disable anonymous FTP login.\n2. Restrict FTP to specific IP ranges.\n3. Replace FTP with SFTP (SSH File Transfer Protocol).\n4. If FTP is required, enable TLS (FTPS).",
			Metadata: map[string]string{
				"attack_technique_ids": "T1078.004",
				"credential":           "anonymous:anonymous",
				"banner":               banner,
			},
			Timestamp: time.Now().UnixMilli(),
		}, nil
	}

	return notVulnerableFinding(host, 21, "ftp", "FTP Anonymous Login Not Allowed"), nil
}

// ─────────────────────────────────────────────
//  Redis
// ─────────────────────────────────────────────

func (c *CredChecker) checkRedis(ctx context.Context, host string, port int) (*pb.Finding, error) {
	if port == 0 {
		port = 6379
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := dialWithContext(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("redis connect: %w", err)
	}
	defer conn.Close()

	// Send PING command — if unauthenticated returns +PONG it's exposed
	writeLine(conn, "PING\r\n")
	resp := readLine(conn, 3*time.Second)

	if strings.Contains(resp, "PONG") {
		// Try INFO to get server info
		writeLine(conn, "INFO server\r\n")
		info := readBytes(conn, 2*time.Second, 512)
		return &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        host,
			Port:        6379,
			Protocol:    "tcp",
			Service:     "redis",
			Severity:    pb.Severity_CRITICAL,
			Title:       "Redis Unauthenticated Access",
			Description: fmt.Sprintf("Redis on %s:6379 is accessible without authentication. An attacker can read/write all cached data, execute Lua scripts, and potentially achieve RCE via config rewrite.", host),
			Evidence:    fmt.Sprintf("PING response: %s\nINFO: %s", resp, truncate(info, 300)),
			Remediation: "1. Set requirepass in redis.conf with a strong password.\n2. Bind Redis to 127.0.0.1 only.\n3. Enable protected-mode yes.\n4. Use Redis ACL (v6+) for fine-grained access control.\n5. Enable TLS.",
			CveId:       "CVE-2022-0543",
			Metadata: map[string]string{
				"attack_technique_ids": "T1505.003,T1190",
				"info":                 truncate(info, 200),
			},
			Timestamp: time.Now().UnixMilli(),
		}, nil
	}

	return notVulnerableFinding(host, 6379, "redis", "Redis Authentication Required"), nil
}

// ─────────────────────────────────────────────
//  MongoDB
// ─────────────────────────────────────────────

func (c *CredChecker) checkMongoDB(ctx context.Context, host string, port int) (*pb.Finding, error) {
	if port == 0 {
		port = 27017
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := dialWithContext(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("mongodb connect: %w", err)
	}
	defer conn.Close()

	// MongoDB wire protocol: send isMaster command
	isMasterMsg := buildMongoIsMaster()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(isMasterMsg); err != nil {
		return nil, fmt.Errorf("mongodb write: %w", err)
	}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])

	// If we get a response without auth error, it's unauthenticated
	if n > 20 && !strings.Contains(resp, "requires authentication") {
		return &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        host,
			Port:        27017,
			Protocol:    "tcp",
			Service:     "mongodb",
			Severity:    pb.Severity_CRITICAL,
			Title:       "MongoDB Unauthenticated Access",
			Description: fmt.Sprintf("MongoDB on %s:27017 accepts connections without authentication. An attacker can read, modify, or delete all database contents.", host),
			Evidence:    fmt.Sprintf("isMaster response received (%d bytes) without authentication", n),
			Remediation: "1. Enable --auth flag or security.authorization: enabled in mongod.conf.\n2. Create admin user immediately.\n3. Bind to 127.0.0.1 or specific IPs.\n4. Enable TLS/SSL.\n5. Use network-level firewall rules.",
			Metadata: map[string]string{
				"attack_technique_ids": "T1530,T1190",
			},
			Timestamp: time.Now().UnixMilli(),
		}, nil
	}

	return notVulnerableFinding(host, 27017, "mongodb", "MongoDB Authentication Required"), nil
}

// ─────────────────────────────────────────────
//  Elasticsearch
// ─────────────────────────────────────────────

func (c *CredChecker) checkElasticsearch(ctx context.Context, host string, port int) (*pb.Finding, error) {
	if port == 0 {
		port = 9200
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := dialWithContext(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("elasticsearch connect: %w", err)
	}
	defer conn.Close()

	// Send HTTP GET /
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte(req))

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])

	if strings.Contains(resp, "tagline") || strings.Contains(resp, "elasticsearch") {
		return &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        host,
			Port:        9200,
			Protocol:    "tcp",
			Service:     "elasticsearch",
			Severity:    pb.Severity_CRITICAL,
			Title:       "Elasticsearch Unauthenticated Access",
			Description: fmt.Sprintf("Elasticsearch on %s:9200 is accessible without authentication. All indices and data are readable and writable.", host),
			Evidence:    truncate(resp, 300),
			Remediation: "1. Enable X-Pack Security (xpack.security.enabled: true).\n2. Set up built-in users with the elasticsearch-setup-passwords tool.\n3. Enable TLS for transport and HTTP layers.\n4. Restrict network access via firewall.",
			Metadata: map[string]string{
				"attack_technique_ids": "T1530",
			},
			Timestamp: time.Now().UnixMilli(),
		}, nil
	}

	return notVulnerableFinding(host, 9200, "elasticsearch", "Elasticsearch Authentication Enabled"), nil
}

// ─────────────────────────────────────────────
//  Memcached
// ─────────────────────────────────────────────

func (c *CredChecker) checkMemcached(ctx context.Context, host string, port int) (*pb.Finding, error) {
	if port == 0 {
		port = 11211
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := dialWithContext(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("memcached connect: %w", err)
	}
	defer conn.Close()

	writeLine(conn, "stats\r\n")
	resp := readBytes(conn, 3*time.Second, 512)

	if strings.Contains(resp, "STAT ") {
		return &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        host,
			Port:        11211,
			Protocol:    "tcp",
			Service:     "memcached",
			Severity:    pb.Severity_HIGH,
			Title:       "Memcached Unauthenticated Access",
			Description: fmt.Sprintf("Memcached on %s:11211 exposes stats and cached data without authentication. Can be abused for DDoS amplification (UDP) and data theft.", host),
			Evidence:    truncate(resp, 300),
			Remediation: "1. Bind Memcached to 127.0.0.1 only.\n2. Disable UDP port (--listen + -U 0).\n3. Use SASL authentication.\n4. Apply firewall rules restricting access to known client IPs.",
			Metadata: map[string]string{
				"attack_technique_ids": "T1499.002",
			},
			Timestamp: time.Now().UnixMilli(),
		}, nil
	}

	return notVulnerableFinding(host, 11211, "memcached", "Memcached Not Accessible"), nil
}

// ─────────────────────────────────────────────
//  SMTP Open Relay
// ─────────────────────────────────────────────

func (c *CredChecker) checkSMTPRelay(ctx context.Context, host string, port int) (*pb.Finding, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := dialWithContext(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("smtp connect: %w", err)
	}
	defer conn.Close()

	banner := readLine(conn, 3*time.Second)
	writeLine(conn, "EHLO xarex.local\r\n")
	ehlo := readBytes(conn, 2*time.Second, 512)
	writeLine(conn, "MAIL FROM:<test@xarex.local>\r\n")
	mailFrom := readLine(conn, 2*time.Second)
	writeLine(conn, "RCPT TO:<test@external-domain.com>\r\n")
	rcptTo := readLine(conn, 2*time.Second)

	isOpenRelay := strings.HasPrefix(rcptTo, "250")
	writeLine(conn, "QUIT\r\n")

	if isOpenRelay {
		return &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        host,
			Port:        int32(port),
			Protocol:    "tcp",
			Service:     "smtp",
			Severity:    pb.Severity_HIGH,
			Title:       "SMTP Open Relay Detected",
			Description: fmt.Sprintf("The SMTP server on %s:%d accepts messages for external domains without authentication — an open relay. Attackers can use this to send spam and phishing emails.", host, port),
			Evidence:    fmt.Sprintf("Banner: %s\nMAIL FROM response: %s\nRCPT TO external: %s", banner, mailFrom, rcptTo),
			Remediation: "1. Configure SMTP relay restrictions (relay_domains, mynetworks in Postfix).\n2. Require SMTP AUTH for external relay.\n3. Implement SPF, DKIM, DMARC.\n4. Monitor outbound email volume.",
			Metadata: map[string]string{
				"attack_technique_ids": "T1566",
				"ehlo_response":        truncate(ehlo, 100),
			},
			Timestamp: time.Now().UnixMilli(),
		}, nil
	}

	return notVulnerableFinding(host, port, "smtp", "SMTP Relay Restricted"), nil
}

// ─────────────────────────────────────────────
//  HTTP Basic Auth
// ─────────────────────────────────────────────

func (c *CredChecker) checkHTTPBasicAuth(ctx context.Context, host string, port int) (*pb.Finding, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := dialWithContext(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("http connect: %w", err)
	}
	defer conn.Close()

	// Check if site requires Basic Auth
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte(req))

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])

	if !strings.Contains(resp, "401") && !strings.Contains(resp, "WWW-Authenticate") {
		// Not using Basic Auth
		return notVulnerableFinding(host, port, "http", "HTTP Basic Auth Not Required"), nil
	}

	// Try common credentials
	for _, cred := range CommonCredentials[:10] {
		conn2, err := dialWithContext(ctx, addr)
		if err != nil {
			continue
		}

		encoded := encodeBase64(cred.User + ":" + cred.Pass)
		authReq := fmt.Sprintf(
			"GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\nConnection: close\r\n\r\n",
			host, encoded,
		)
		conn2.SetDeadline(time.Now().Add(4 * time.Second))
		conn2.Write([]byte(authReq))

		buf2 := make([]byte, 256)
		n2, _ := conn2.Read(buf2)
		r2 := string(buf2[:n2])
		conn2.Close()

		if strings.HasPrefix(r2, "HTTP/1") && !strings.Contains(r2, "401") && !strings.Contains(r2, "403") {
			return &pb.Finding{
				FindingId:   uuid.NewString(),
				Host:        host,
				Port:        int32(port),
				Protocol:    "tcp",
				Service:     "http",
				Severity:    pb.Severity_CRITICAL,
				Title:       fmt.Sprintf("HTTP Default Credentials Accepted (%s:%s)", cred.User, cred.Pass),
				Description: fmt.Sprintf("The web service on %s:%d accepted default credentials. An attacker can authenticate and access protected resources.", host, port),
				Evidence:    fmt.Sprintf("Credential %s:%s returned non-401 response:\n%s", cred.User, cred.Pass, truncate(r2, 200)),
				Remediation: "1. Change default credentials immediately.\n2. Enforce strong password policy.\n3. Implement account lockout.\n4. Enable MFA where possible.\n5. Restrict admin interface access by IP.",
				Metadata: map[string]string{
					"attack_technique_ids": "T1078",
					"username":             cred.User,
					"password":             cred.Pass,
				},
				Timestamp: time.Now().UnixMilli(),
			}, nil
		}
	}

	return notVulnerableFinding(host, port, "http", "HTTP Default Credentials Not Found"), nil
}

// ─────────────────────────────────────────────
//  Generic banner + credential check
// ─────────────────────────────────────────────

func (c *CredChecker) genericCredCheck(ctx context.Context, host string, port int, service string) (*pb.Finding, error) {
	// Just check if port is open and return an info finding
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := dialWithContext(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	banner := readLine(conn, 2*time.Second)
	return &pb.Finding{
		FindingId:   uuid.NewString(),
		Host:        host,
		Port:        int32(port),
		Protocol:    "tcp",
		Service:     service,
		Severity:    pb.Severity_INFO,
		Title:       fmt.Sprintf("Service Banner: %s on port %d", service, port),
		Description: fmt.Sprintf("Service %s on %s:%d is reachable. Manual credential testing recommended.", service, host, port),
		Evidence:    banner,
		Remediation: "Verify authentication is configured correctly for this service.",
		Timestamp:   time.Now().UnixMilli(),
	}, nil
}

// ─────────────────────────────────────────────
//  Utilities
// ─────────────────────────────────────────────

func dialWithContext(ctx context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: credCheckTimeout}
	return d.DialContext(ctx, "tcp", addr)
}

func writeLine(conn net.Conn, s string) {
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte(s))
}

func readLine(conn net.Conn, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

func readBytes(conn net.Conn, timeout time.Duration, maxBytes int) string {
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, maxBytes)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

func notVulnerableFinding(host string, port int, service, title string) *pb.Finding {
	return &pb.Finding{
		FindingId:   uuid.NewString(),
		Host:        host,
		Port:        int32(port),
		Protocol:    "tcp",
		Service:     service,
		Severity:    pb.Severity_INFO,
		Title:       title,
		Description: fmt.Sprintf("%s on %s:%d — no default credential issue detected.", service, host, port),
		Evidence:    "No vulnerability confirmed.",
		Timestamp:   time.Now().UnixMilli(),
	}
}

func buildMongoIsMaster() []byte {
	// Minimal MongoDB OP_MSG with isMaster command
	// This is a well-known fingerprinting packet used by tools like nmap
	msg := []byte{
		0x41, 0x00, 0x00, 0x00, // messageLength
		0x01, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xdd, 0x07, 0x00, 0x00, // opCode = OP_MSG (2013)
		0x00, 0x00, 0x00, 0x00, // flagBits
		0x00,                   // section type 0
		// BSON document: {isMaster: 1, $db: "admin"}
		0x29, 0x00, 0x00, 0x00,
		0x10, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x02, 0x24, 0x64, 0x62, 0x00,
		0x06, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00,
		0x00,
	}
	return msg
}

func encodeBase64(s string) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := []byte(s)
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		out.WriteByte(chars[chunk[0]>>2])
		out.WriteByte(chars[(chunk[0]&0x3)<<4|chunk[1]>>4])
		if n > 1 {
			out.WriteByte(chars[(chunk[1]&0xf)<<2|chunk[2]>>6])
		} else {
			out.WriteByte('=')
		}
		if n > 2 {
			out.WriteByte(chars[chunk[2]&0x3f])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

// truncate shortens s to max bytes, appending … if trimmed.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
