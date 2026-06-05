package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xarex/probe/grpc/pb"
)

const (
	bannerReadTimeout  = 3 * time.Second
	bannerReadMaxBytes = 2048
	httpTimeout        = 5 * time.Second
)

// Fingerprinter attempts to identify the service and version running on an open port
// by sending protocol-specific probes and parsing the response.
type Fingerprinter struct {
	logger *slog.Logger
}

// NewFingerprinter returns a ready-to-use Fingerprinter.
func NewFingerprinter(logger *slog.Logger) *Fingerprinter {
	return &Fingerprinter{logger: logger}
}

// Fingerprint enriches port with service, banner, and version information.
// The original Port is returned unchanged if fingerprinting fails gracefully.
func (f *Fingerprinter) Fingerprint(ctx context.Context, host string, port *pb.Port) (*pb.Port, error) {
	result := *port // copy

	probe, ok := selectProbe(int(port.Number), port.Service)
	if !ok {
		// Generic banner grab.
		banner, version, err := f.grabBanner(ctx, host, int(port.Number), nil)
		if err != nil {
			f.logger.Debug("banner grab failed", "host", host, "port", port.Number, "error", err)
			return &result, nil
		}
		result.Banner = banner
		result.Version = version
		result.Service = inferServiceFromBanner(banner, port.Service)
		return &result, nil
	}

	svc, banner, version, err := probe(ctx, host, int(port.Number))
	if err != nil {
		f.logger.Debug("service probe failed",
			"host", host, "port", port.Number, "service", port.Service, "error", err)
		return &result, nil
	}

	result.Service = svc
	result.Banner = banner
	result.Version = version
	f.logger.Info("fingerprint",
		"host", host, "port", port.Number,
		"service", svc, "version", version,
	)
	return &result, nil
}

// probeFunc is the signature for a service-specific probe function.
// It returns (service, banner, version, error).
type probeFunc func(ctx context.Context, host string, port int) (string, string, string, error)

// selectProbe chooses the right probe function based on port number or service hint.
func selectProbe(portNum int, hint string) (probeFunc, bool) {
	switch {
	case portNum == 80 || hint == "http" || hint == "http-alt" || hint == "http-alt2":
		return probeHTTP(false), true
	case portNum == 443 || portNum == 8443 || hint == "https" || hint == "https-alt":
		return probeHTTP(true), true
	case portNum == 22 || hint == "ssh":
		return probeSSH, true
	case portNum == 21 || hint == "ftp":
		return probeFTP, true
	case portNum == 25 || portNum == 587 || portNum == 465 || hint == "smtp" || hint == "submission" || hint == "smtps":
		return probeSMTP, true
	case portNum == 3306 || hint == "mysql":
		return probeMySQL, true
	case portNum == 6379 || portNum == 6380 || hint == "redis" || hint == "redis-tls":
		return probeRedis, true
	case portNum == 27017 || portNum == 27018 || portNum == 27019 || hint == "mongodb":
		return probeMongoDB, true
	default:
		return nil, false
	}
}

// ─────────────────────────────────────────────
//  Generic banner grab
// ─────────────────────────────────────────────

func (f *Fingerprinter) grabBanner(ctx context.Context, host string, port int, sendData []byte) (banner, version string, err error) {
	dialCtx, cancel := context.WithTimeout(ctx, bannerReadTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerReadTimeout))

	if len(sendData) > 0 {
		if _, err := conn.Write(sendData); err != nil {
			return "", "", fmt.Errorf("send probe: %w", err)
		}
	}

	buf := make([]byte, bannerReadMaxBytes)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read banner: %w", err)
	}
	if n == 0 {
		return "", "", nil
	}
	raw := strings.TrimSpace(string(buf[:n]))
	return raw, extractVersion(raw), nil
}

// extractVersion tries to pull a semver-ish string out of a banner.
func extractVersion(banner string) string {
	// Look for patterns like "OpenSSH_9.3", "2.0.52", "5.7.42-log", etc.
	words := strings.Fields(banner)
	for _, w := range words {
		w = strings.Trim(w, ",;()")
		if looksLikeVersion(w) {
			return w
		}
	}
	return ""
}

func looksLikeVersion(s string) bool {
	if len(s) < 3 || len(s) > 32 {
		return false
	}
	dotCount := strings.Count(s, ".")
	if dotCount == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}

func inferServiceFromBanner(banner, hint string) string {
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "ssh"):
		return "ssh"
	case strings.Contains(lower, "ftp"):
		return "ftp"
	case strings.Contains(lower, "smtp") || strings.Contains(lower, "postfix") || strings.Contains(lower, "sendmail"):
		return "smtp"
	case strings.Contains(lower, "http"):
		return "http"
	case strings.Contains(lower, "redis"):
		return "redis"
	case strings.Contains(lower, "mysql") || strings.Contains(lower, "mariadb"):
		return "mysql"
	case strings.Contains(lower, "mongo"):
		return "mongodb"
	default:
		return hint
	}
}

// ─────────────────────────────────────────────
//  HTTP / HTTPS probe
// ─────────────────────────────────────────────

func probeHTTP(useTLS bool) probeFunc {
	return func(ctx context.Context, host string, port int) (string, string, string, error) {
		scheme := "http"
		if useTLS {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, strconv.Itoa(port)))

		transport := &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DisableKeepAlives: true,
		}
		client := &http.Client{
			Timeout:   httpTimeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", "", "", fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("User-Agent", "Xarex-Probe/1.0")

		resp, err := client.Do(req)
		if err != nil {
			return "", "", "", fmt.Errorf("http get: %w", err)
		}
		defer resp.Body.Close()

		server := resp.Header.Get("Server")
		xPoweredBy := resp.Header.Get("X-Powered-By")
		banner := fmt.Sprintf("HTTP/%s %d; Server: %s; X-Powered-By: %s",
			resp.Proto, resp.StatusCode, server, xPoweredBy)

		svc := "http"
		if useTLS {
			svc = "https"
		}
		version := extractVersion(server)
		if version == "" {
			version = extractVersion(xPoweredBy)
		}

		return svc, banner, version, nil
	}
}

// ─────────────────────────────────────────────
//  SSH probe
// ─────────────────────────────────────────────

func probeSSH(ctx context.Context, host string, port int) (string, string, string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, bannerReadTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", "", "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerReadTimeout))

	// SSH sends its version banner immediately on connect.
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", "", fmt.Errorf("read ssh banner: %w", err)
	}

	banner := strings.TrimSpace(line)
	// Typical format: SSH-2.0-OpenSSH_9.3
	version := ""
	if strings.HasPrefix(banner, "SSH-") {
		parts := strings.SplitN(banner, "-", 3)
		if len(parts) == 3 {
			version = parts[2]
		}
	}

	return "ssh", banner, version, nil
}

// ─────────────────────────────────────────────
//  FTP probe
// ─────────────────────────────────────────────

func probeFTP(ctx context.Context, host string, port int) (string, string, string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, bannerReadTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", "", "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerReadTimeout))

	reader := bufio.NewReader(conn)
	var banner strings.Builder
	for {
		line, err := reader.ReadString('\n')
		banner.WriteString(line)
		if err != nil || !strings.HasPrefix(line, "220-") {
			break
		}
	}

	b := strings.TrimSpace(banner.String())
	return "ftp", b, extractVersion(b), nil
}

// ─────────────────────────────────────────────
//  SMTP probe
// ─────────────────────────────────────────────

func probeSMTP(ctx context.Context, host string, port int) (string, string, string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, bannerReadTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", "", "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerReadTimeout))

	reader := bufio.NewReader(conn)
	// Read greeting (may be multi-line starting with 220-).
	var banner strings.Builder
	for {
		line, err := reader.ReadString('\n')
		banner.WriteString(line)
		if err != nil {
			break
		}
		// Multi-line replies use "220-"; single-line uses "220 ".
		trimmed := strings.TrimSpace(line)
		if len(trimmed) >= 4 && trimmed[3] == ' ' {
			break
		}
	}

	b := strings.TrimSpace(banner.String())
	return "smtp", b, extractVersion(b), nil
}

// ─────────────────────────────────────────────
//  MySQL probe
// ─────────────────────────────────────────────

func probeMySQL(ctx context.Context, host string, port int) (string, string, string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, bannerReadTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", "", "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerReadTimeout))

	// MySQL sends a server greeting packet on connect.
	// Packet: 4-byte header (3 len + 1 seq), then payload.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", "", "", fmt.Errorf("read mysql header: %w", err)
	}
	payloadLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if payloadLen > 4096 {
		payloadLen = 4096
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return "", "", "", fmt.Errorf("read mysql payload: %w", err)
	}

	// Protocol version is payload[0]. Version string starts at payload[1], null-terminated.
	version := ""
	if len(payload) > 1 {
		nullIdx := strings.IndexByte(string(payload[1:]), 0)
		if nullIdx >= 0 {
			version = string(payload[1 : 1+nullIdx])
		}
	}
	banner := fmt.Sprintf("MySQL protocol=%d version=%s", payload[0], version)
	return "mysql", banner, version, nil
}

// ─────────────────────────────────────────────
//  Redis probe
// ─────────────────────────────────────────────

func probeRedis(ctx context.Context, host string, port int) (string, string, string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, bannerReadTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", "", "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerReadTimeout))

	// Send inline INFO command.
	if _, err := conn.Write([]byte("INFO server\r\n")); err != nil {
		return "", "", "", fmt.Errorf("send INFO: %w", err)
	}

	buf := make([]byte, bannerReadMaxBytes)
	n, _ := conn.Read(buf)
	if n == 0 {
		return "redis", "", "", nil
	}

	raw := string(buf[:n])
	version := extractRedisVersion(raw)
	// Truncate banner for storage.
	banner := strings.SplitN(raw, "\r\n", 5)[0]
	return "redis", banner, version, nil
}

func extractRedisVersion(info string) string {
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redis_version:") {
			return strings.TrimPrefix(line, "redis_version:")
		}
	}
	return ""
}

// ─────────────────────────────────────────────
//  MongoDB probe
// ─────────────────────────────────────────────

func probeMongoDB(ctx context.Context, host string, port int) (string, string, string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, bannerReadTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", "", "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerReadTimeout))

	// Minimal OP_MSG isMaster / hello query.
	// We send a raw MongoDB wire protocol message: OP_QUERY on admin.$cmd for {isMaster:1}.
	// Hex-encoded minimal OP_QUERY for {isMaster:1}:
	query := buildMongoIsMasterQuery()
	if _, err := conn.Write(query); err != nil {
		return "", "", "", fmt.Errorf("send mongo query: %w", err)
	}

	buf := make([]byte, bannerReadMaxBytes)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return "", "", "", fmt.Errorf("read mongo response: %w", err)
	}

	banner := fmt.Sprintf("mongodb response bytes=%d", n)
	version := extractMongoVersion(buf[:n])
	return "mongodb", banner, version, nil
}

// buildMongoIsMasterQuery returns the wire bytes for a minimal isMaster command.
func buildMongoIsMasterQuery() []byte {
	// OP_QUERY (opcode 2004):
	// MsgHeader (16) + flags(4) + collection("admin.$cmd\x00",12) + skip(4) + ret(4) + doc
	// BSON doc for {isMaster:1}: length(4) + type(1,Int32) + key("isMaster\x00") + val(4) + terminator(1)
	bsonDoc := []byte{
		0x13, 0x00, 0x00, 0x00, // doc length = 19
		0x10,                                           // type int32
		0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, // "isMaster\0"
		0x01, 0x00, 0x00, 0x00, // value = 1
		0x00, // end of doc
	}

	collName := []byte("admin.$cmd\x00")
	// Total message length.
	totalLen := 16 + 4 + len(collName) + 4 + 4 + len(bsonDoc)

	msg := make([]byte, 0, totalLen)
	putInt32 := func(v int32) {
		b := []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
		msg = append(msg, b...)
	}

	putInt32(int32(totalLen)) // messageLength
	putInt32(1)               // requestID
	putInt32(0)               // responseTo
	putInt32(2004)            // opCode OP_QUERY
	putInt32(0)               // flags
	msg = append(msg, collName...)
	putInt32(0) // numberToSkip
	putInt32(1) // numberToReturn
	msg = append(msg, bsonDoc...)

	return msg
}

func extractMongoVersion(data []byte) string {
	// The version string appears in the BSON response as a key "version".
	// Simple scan: look for the byte sequence "version" followed by string type.
	key := []byte("version\x00")
	for i := 0; i+len(key)+5 < len(data); i++ {
		if data[i] == 0x02 { // BSON string type
			if string(data[i+1:i+1+len(key)]) == string(key) {
				// String: 4-byte length then chars.
				start := i + 1 + len(key)
				if start+4 > len(data) {
					break
				}
				strLen := int(data[start]) | int(data[start+1])<<8 |
					int(data[start+2])<<16 | int(data[start+3])<<24
				end := start + 4 + strLen - 1 // exclude null terminator
				if end > len(data) {
					break
				}
				return string(data[start+4 : end])
			}
		}
	}
	return ""
}
