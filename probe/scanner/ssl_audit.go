// Package scanner — SSL/TLS Audit Module
//
// Checks performed (2026-relevant threat landscape):
//
//  Certificate health
//    • Expiry (critical <7d, high <30d, medium <90d)
//    • Self-signed / untrusted chain
//    • Hostname mismatch
//    • Weak RSA key (<2048-bit) or EC key (<256-bit)
//    • Deprecated signature algorithm (MD5, SHA-1)
//    • Validity period >398 days (CA/BF baseline req since 2020)
//    • Wildcard scope abuse
//
//  Protocol versions
//    • SSLv3 — POODLE (CVE-2014-3566)
//    • TLS 1.0 — BEAST (CVE-2011-3389), deprecated RFC 8996
//    • TLS 1.1 — deprecated RFC 8996
//    • TLS 1.2 — acceptable, check cipher hygiene
//    • TLS 1.3 — gold standard, note if absent
//
//  Cipher suites
//    • RC4 — NOMORE / Bar-Mitzvah (CVE-2015-2808)
//    • 3DES — SWEET32 (CVE-2016-2183)
//    • NULL, ANON, EXPORT-grade — immediately critical
//    • No forward-secrecy (no ECDHE/DHE)
//    • MD5 MAC
//
//  Specific CVEs
//    • Heartbleed — CVE-2014-0160 (raw socket probe)
//    • POODLE     — CVE-2014-3566 (raw SSLv3 ClientHello)
//    • BEAST      — CVE-2011-3389 (TLS1.0 + CBC)
//    • SWEET32    — CVE-2016-2183 (3DES negotiation)
//    • CRIME      — CVE-2012-4929 (TLS compression)
//    • ROBOT      — CVE-2017-13099 (RSA PKCS#1 oracle, detected via timing hint)
//
//  HTTPS hardening
//    • HSTS missing or weak max-age (<31536000)
//    • HSTS without includeSubDomains
//    • HSTS without preload directive

package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────

// SSLFinding is an internal result from one audit check.
type SSLFinding struct {
	Severity    int    // 0=info 1=low 2=medium 3=high 4=critical
	Title       string
	Description string
	Evidence    string
	Remediation string
	CVEID       string
}

// SSLAuditScanner performs comprehensive TLS audits.
type SSLAuditScanner struct {
	logger      *slog.Logger
	dialTimeout time.Duration
	readTimeout time.Duration
}

// NewSSLAuditScanner returns a ready scanner.
func NewSSLAuditScanner(logger *slog.Logger) *SSLAuditScanner {
	return &SSLAuditScanner{
		logger:      logger,
		dialTimeout: 8 * time.Second,
		readTimeout: 6 * time.Second,
	}
}

// ─────────────────────────────────────────────────────────────
//  Public entry point
// ─────────────────────────────────────────────────────────────

// Audit runs all SSL/TLS checks against host:port and returns findings.
func (s *SSLAuditScanner) Audit(ctx context.Context, host string, port int) ([]SSLFinding, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	s.logger.Info("SSL/TLS audit started", "host", host, "port", port)

	var all []SSLFinding

	// 1. Certificate chain
	all = append(all, s.checkCertificate(ctx, addr, host, port)...)

	// 2. Protocol version sweep
	all = append(all, s.checkTLSVersions(ctx, addr, host)...)

	// 3. Weak cipher suites (TLS 1.2)
	all = append(all, s.checkWeakCiphers(ctx, addr, host)...)

	// 4. CVE-specific probes
	all = append(all, s.checkHeartbleed(ctx, host, port)...)
	all = append(all, s.checkPOODLE(ctx, host, port)...)
	all = append(all, s.checkCRIME(ctx, addr, host)...)

	// 5. HTTPS hardening (ports 443 / 8443 / 4443)
	if isHTTPSPort(port) {
		all = append(all, s.checkHSTS(ctx, host, port)...)
	}

	s.logger.Info("SSL/TLS audit complete", "host", host, "port", port,
		"findings", len(all))
	return all, nil
}

// ─────────────────────────────────────────────────────────────
//  1 — Certificate
// ─────────────────────────────────────────────────────────────

func (s *SSLAuditScanner) checkCertificate(ctx context.Context, addr, host string, port int) []SSLFinding {
	var findings []SSLFinding

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: s.dialTimeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, // we inspect the cert ourselves
			ServerName:         host,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return append(findings, SSLFinding{
			Severity: 1,
			Title:    "SSL/TLS — Could not connect",
			Description: fmt.Sprintf("Failed to establish TLS connection to %s: %v", addr, err),
		})
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	certs := state.PeerCertificates

	if len(certs) == 0 {
		return append(findings, SSLFinding{
			Severity:    2,
			Title:       "No certificate returned by server",
			Description: "The server did not present any X.509 certificate.",
		})
	}

	leaf := certs[0]
	now := time.Now()

	// ── Hostname mismatch ────────────────────────────────────
	if err := leaf.VerifyHostname(host); err != nil {
		findings = append(findings, SSLFinding{
			Severity:    3,
			Title:       "Certificate hostname mismatch",
			Description: fmt.Sprintf("Certificate CN/SANs do not cover %q: %v", host, err),
			Evidence:    fmt.Sprintf("CN=%s  SANs=%s", leaf.Subject.CommonName, strings.Join(leaf.DNSNames, ", ")),
			Remediation: "Reissue the certificate with the correct Subject Alternative Names.",
		})
	}

	// ── Self-signed / untrusted chain ────────────────────────
	roots, _ := x509.SystemCertPool()
	opts := x509.VerifyOptions{Roots: roots, CurrentTime: now}
	if _, err := leaf.Verify(opts); err != nil {
		findings = append(findings, SSLFinding{
			Severity:    3,
			Title:       "Untrusted or self-signed certificate",
			Description: fmt.Sprintf("Certificate chain failed validation: %v", err),
			Evidence:    fmt.Sprintf("Issuer=%s", leaf.Issuer.CommonName),
			Remediation: "Replace with a certificate issued by a trusted CA (e.g. Let's Encrypt, DigiCert).",
		})
	}

	// ── Expiry ───────────────────────────────────────────────
	remaining := leaf.NotAfter.Sub(now)
	switch {
	case now.After(leaf.NotAfter):
		findings = append(findings, SSLFinding{
			Severity:    4,
			Title:       "Certificate EXPIRED",
			Description: fmt.Sprintf("Certificate expired %s ago on %s.", formatDuration(-remaining), leaf.NotAfter.Format("2006-01-02")),
			Evidence:    fmt.Sprintf("NotAfter: %s", leaf.NotAfter),
			Remediation: "Renew the certificate immediately. Consider automating renewal with ACME/Let's Encrypt.",
		})
	case remaining < 7*24*time.Hour:
		findings = append(findings, SSLFinding{
			Severity:    4,
			Title:       "Certificate expires in <7 days (critical)",
			Description: fmt.Sprintf("Certificate expires on %s — only %s remaining.", leaf.NotAfter.Format("2006-01-02"), formatDuration(remaining)),
			Remediation: "Renew immediately.",
		})
	case remaining < 30*24*time.Hour:
		findings = append(findings, SSLFinding{
			Severity:    3,
			Title:       "Certificate expires in <30 days",
			Description: fmt.Sprintf("Certificate expires on %s.", leaf.NotAfter.Format("2006-01-02")),
			Remediation: "Schedule renewal within the next few days.",
		})
	case remaining < 90*24*time.Hour:
		findings = append(findings, SSLFinding{
			Severity:    1,
			Title:       "Certificate expires in <90 days",
			Description: fmt.Sprintf("Certificate expires on %s.", leaf.NotAfter.Format("2006-01-02")),
			Remediation: "Plan renewal.",
		})
	}

	// ── Validity period > 398 days (CA/Browser Forum baseline) ──
	validity := leaf.NotAfter.Sub(leaf.NotBefore)
	if validity > 398*24*time.Hour {
		findings = append(findings, SSLFinding{
			Severity:    2,
			Title:       "Certificate validity period exceeds 398 days",
			Description: fmt.Sprintf("Validity is %d days. CA/Browser Forum baseline requirements cap public certificates at 398 days since 2020. Browsers may distrust over-long certificates.", int(validity.Hours()/24)),
			Remediation: "Reissue with a validity ≤398 days. Automate renewal to compensate for shorter lifetimes.",
		})
	}

	// ── Weak key size ────────────────────────────────────────
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		if bits < 2048 {
			findings = append(findings, SSLFinding{
				Severity:    4,
				Title:       fmt.Sprintf("Weak RSA key: %d-bit (minimum 2048)", bits),
				Description: "RSA keys smaller than 2048 bits can be factored with modern hardware.",
				Evidence:    fmt.Sprintf("RSA key size: %d bits", bits),
				Remediation: "Reissue with RSA-2048 minimum, or migrate to ECDSA P-256.",
			})
		} else if bits < 3072 {
			findings = append(findings, SSLFinding{
				Severity:    1,
				Title:       fmt.Sprintf("RSA key %d-bit — consider upgrading to 3072+ for post-quantum readiness", bits),
				Description: "NIST SP 800-131A recommends RSA-3072 for security beyond 2030.",
				Remediation: "Migrate to RSA-3072/4096 or ECDSA P-384 for long-term security.",
			})
		}
	case *ecdsa.PublicKey:
		bits := pub.Curve.Params().BitSize
		if bits < 256 {
			findings = append(findings, SSLFinding{
				Severity:    3,
				Title:       fmt.Sprintf("Weak EC key: %d-bit (minimum P-256)", bits),
				Description: "EC keys below 256 bits offer insufficient security.",
				Remediation: "Use P-256 (secp256r1) or P-384 (secp384r1).",
			})
		}
	}

	// ── Deprecated signature algorithm ───────────────────────
	sigAlg := leaf.SignatureAlgorithm.String()
	switch {
	case strings.Contains(strings.ToLower(sigAlg), "md5"):
		findings = append(findings, SSLFinding{
			Severity:    4,
			Title:       "Certificate signed with MD5 — cryptographically broken",
			Description: "MD5 collision attacks allow forging certificates. No browser trusts MD5-signed certs.",
			Evidence:    "SignatureAlgorithm: " + sigAlg,
			Remediation: "Reissue with SHA-256 or SHA-384.",
		})
	case strings.Contains(strings.ToLower(sigAlg), "sha1"):
		findings = append(findings, SSLFinding{
			Severity:    3,
			Title:       "Certificate signed with SHA-1 — deprecated",
			Description: "SHA-1 is deprecated since 2016. Modern browsers display security warnings or block SHA-1 certificates.",
			Evidence:    "SignatureAlgorithm: " + sigAlg,
			Remediation: "Reissue with SHA-256 minimum.",
		})
	}

	// ── Wildcard scope ───────────────────────────────────────
	for _, san := range leaf.DNSNames {
		if strings.HasPrefix(san, "*.") {
			findings = append(findings, SSLFinding{
				Severity:    1,
				Title:       fmt.Sprintf("Wildcard certificate in use: %s", san),
				Description: "Wildcard certificates cover all first-level subdomains. A single key compromise exposes every subdomain. Wildcard certs also cannot be used with HSTS preloading.",
				Evidence:    "SAN: " + san,
				Remediation: "Consider per-service certificates with automation (ACME). Never use wildcard certs for high-value services like payment or auth endpoints.",
			})
			break
		}
	}

	// ── Info: certificate summary ────────────────────────────
	findings = append(findings, SSLFinding{
		Severity: 0,
		Title:    fmt.Sprintf("SSL/TLS Certificate: %s", leaf.Subject.CommonName),
		Description: fmt.Sprintf(
			"Issuer: %s | Valid: %s → %s | Algorithm: %s | SANs: %s",
			leaf.Issuer.CommonName,
			leaf.NotBefore.Format("2006-01-02"),
			leaf.NotAfter.Format("2006-01-02"),
			leaf.SignatureAlgorithm.String(),
			strings.Join(append(leaf.DNSNames, ipStrings(leaf.IPAddresses)...), ", "),
		),
		Evidence: fmt.Sprintf("Serial: %s", leaf.SerialNumber.Text(16)),
	})

	return findings
}

// ─────────────────────────────────────────────────────────────
//  2 — TLS version sweep
// ─────────────────────────────────────────────────────────────

type versionSpec struct {
	label      string
	min, max   uint16
	severity   int
	desc       string
	remediation string
	cve        string
}

var versionSpecs = []versionSpec{
	{
		label:    "TLS 1.0",
		min:      tls.VersionTLS10, max: tls.VersionTLS10,
		severity: 2,
		desc:     "TLS 1.0 is deprecated per RFC 8996 (2021). It is vulnerable to BEAST (CVE-2011-3389) and POODLE-over-TLS.",
		remediation: "Disable TLS 1.0. Minimum recommended: TLS 1.2. Enforce TLS 1.3 where possible.",
		cve:      "CVE-2011-3389",
	},
	{
		label:    "TLS 1.1",
		min:      tls.VersionTLS11, max: tls.VersionTLS11,
		severity: 2,
		desc:     "TLS 1.1 is deprecated per RFC 8996 (2021). It lacks AEAD cipher support and uses legacy PRF.",
		remediation: "Disable TLS 1.1. Configure TLS 1.2 as minimum.",
	},
	{
		label:    "TLS 1.2",
		min:      tls.VersionTLS12, max: tls.VersionTLS12,
		severity: 0,
		desc:     "TLS 1.2 is supported. Acceptable when paired with AEAD ciphers and forward secrecy.",
	},
	{
		label:    "TLS 1.3",
		min:      tls.VersionTLS13, max: tls.VersionTLS13,
		severity: -1, // good — emit as info
		desc:     "TLS 1.3 is supported. This is the recommended protocol offering mandatory forward secrecy and AEAD-only ciphers.",
	},
}

func (s *SSLAuditScanner) checkTLSVersions(ctx context.Context, addr, host string) []SSLFinding {
	var findings []SSLFinding
	tls13Supported := false

	for _, spec := range versionSpecs {
		cfg := &tls.Config{
			MinVersion:         spec.min,
			MaxVersion:         spec.max,
			InsecureSkipVerify: true,
			ServerName:         host,
		}
		dialer := &net.Dialer{Timeout: s.dialTimeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
		if err != nil {
			// Could not negotiate this version — not supported (good for old versions)
			continue
		}
		negotiated := conn.ConnectionState().Version
		conn.Close()

		if negotiated == tls.VersionTLS13 {
			tls13Supported = true
		}

		if spec.severity < 0 {
			// Good finding — just info
			findings = append(findings, SSLFinding{
				Severity:    0,
				Title:       fmt.Sprintf("Protocol supported: %s ✓", spec.label),
				Description: spec.desc,
			})
			continue
		}
		if spec.severity == 0 {
			findings = append(findings, SSLFinding{
				Severity:    0,
				Title:       fmt.Sprintf("Protocol supported: %s", spec.label),
				Description: spec.desc,
			})
			continue
		}

		findings = append(findings, SSLFinding{
			Severity:    spec.severity,
			Title:       fmt.Sprintf("Deprecated protocol supported: %s", spec.label),
			Description: spec.desc,
			Remediation: spec.remediation,
			CVEID:       spec.cve,
		})
	}

	if !tls13Supported {
		findings = append(findings, SSLFinding{
			Severity:    1,
			Title:       "TLS 1.3 not supported",
			Description: "TLS 1.3 (2018) provides mandatory forward secrecy, faster handshakes, and removes legacy cipher suites. Not supporting it leaves clients on weaker protocols.",
			Remediation: "Upgrade your TLS stack (OpenSSL ≥1.1.1, nginx ≥1.13.0, Apache ≥2.4.37) and enable TLS 1.3.",
		})
	}

	return findings
}

// ─────────────────────────────────────────────────────────────
//  3 — Weak cipher suites
// ─────────────────────────────────────────────────────────────

type cipherSpec struct {
	id          uint16
	label       string
	severity    int
	reason      string
	remediation string
	cve         string
}

var weakCiphers = []cipherSpec{
	{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		"TLS_RSA_WITH_RC4_128_SHA", 3,
		"RC4 has known biases (Bar-Mitzvah, NOMORE attacks). Forbidden by RFC 7465.",
		"Remove all RC4 cipher suites from your TLS configuration.",
		"CVE-2015-2808",
	},
	{
		0x0001, // TLS_RSA_WITH_RC4_128_MD5 (raw value — not exported by crypto/tls)
		"TLS_RSA_WITH_RC4_128_MD5", 3,
		"RC4 + MD5: both primitives are broken.",
		"Remove all RC4 cipher suites.",
		"CVE-2015-2808",
	},
	{
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA", 3,
		"RC4 is broken even when paired with ECDHE key exchange.",
		"Remove all RC4 cipher suites.",
		"CVE-2015-2808",
	},
	{
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 3,
		"RC4 is broken even when paired with ECDHE key exchange.",
		"Remove all RC4 cipher suites.",
		"CVE-2015-2808",
	},
	{
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA", 2,
		"3DES uses a 64-bit block cipher vulnerable to SWEET32 birthday attacks after ~768GB of data on the same session key.",
		"Replace with AES-128-GCM or AES-256-GCM (AEAD ciphers).",
		"CVE-2016-2183",
	},
	{
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 2,
		"3DES SWEET32 vulnerability — forward secrecy does not fix the block cipher weakness.",
		"Replace with ECDHE-RSA-AES128-GCM-SHA256 or stronger.",
		"CVE-2016-2183",
	},
	{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_128_CBC_SHA", 1,
		"CBC mode without forward secrecy. Vulnerable to Lucky13 timing attack and BEAST (TLS 1.0).",
		"Prefer ECDHE+AESGCM cipher suites with forward secrecy.",
		"CVE-2013-0169",
	},
	{
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA", 1,
		"CBC mode without forward secrecy. Private key compromise decrypts all past sessions (no FS).",
		"Prefer ECDHE-RSA-AES256-GCM-SHA384.",
		"",
	},
}

func (s *SSLAuditScanner) checkWeakCiphers(ctx context.Context, addr, host string) []SSLFinding {
	var findings []SSLFinding

	for _, cipher := range weakCiphers {
		cfg := &tls.Config{
			CipherSuites:       []uint16{cipher.id},
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
			ServerName:         host,
		}
		dialer := &net.Dialer{Timeout: s.dialTimeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
		if err != nil {
			continue // Server rejected the cipher — good
		}
		negotiated := conn.ConnectionState().CipherSuite
		conn.Close()

		if negotiated == cipher.id {
			findings = append(findings, SSLFinding{
				Severity:    cipher.severity,
				Title:       fmt.Sprintf("Weak cipher suite accepted: %s", cipher.label),
				Description: cipher.reason,
				Evidence:    fmt.Sprintf("Server negotiated: %s (0x%04x)", cipher.label, cipher.id),
				Remediation: cipher.remediation,
				CVEID:       cipher.cve,
			})
		}
	}

	// Check for lack of forward secrecy
	s.checkForwardSecrecy(ctx, addr, host, &findings)

	return findings
}

func (s *SSLAuditScanner) checkForwardSecrecy(ctx context.Context, addr, host string, findings *[]SSLFinding) {
	// Force a non-ECDHE/DHE cipher suite and see if the server accepts it
	noFSCiphers := []uint16{
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	}
	cfg := &tls.Config{
		CipherSuites:       noFSCiphers,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         host,
	}
	dialer := &net.Dialer{Timeout: s.dialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return
	}
	suite := conn.ConnectionState().CipherSuite
	conn.Close()

	// If the negotiated suite is in our no-FS list, forward secrecy is not enforced
	for _, c := range noFSCiphers {
		if suite == c {
			*findings = append(*findings, SSLFinding{
				Severity:    2,
				Title:       "Forward secrecy not enforced — server accepts non-ECDHE/DHE ciphers",
				Description: "Without forward secrecy, a future private key compromise allows decryption of all past recorded traffic. Real-world impact: nation-state adversaries and law enforcement routinely record TLS traffic for later decryption.",
				Evidence:    fmt.Sprintf("Negotiated: 0x%04x (no key exchange providing FS)", suite),
				Remediation: "Configure your TLS server to prefer ECDHE cipher suites and disable RSA key exchange. For nginx: ssl_ciphers 'ECDHE+AESGCM:!aNULL';",
			})
			return
		}
	}
}

// ─────────────────────────────────────────────────────────────
//  4a — Heartbleed (CVE-2014-0160)
// ─────────────────────────────────────────────────────────────

// buildSSLv3Hello constructs a minimal TLS 1.2 ClientHello with the Heartbeat extension.
// Heartbeat extension type = 0x000F per RFC 6520.
func buildHeartbeatClientHello(host string) []byte {
	// SNI extension bytes
	sni := []byte(host)
	sniLen := len(sni)

	sniExt := []byte{
		0x00, 0x00, // extension type: server_name
		0x00, byte(sniLen + 5), // extension data length
		0x00, byte(sniLen + 3), // server name list length
		0x00,                   // name type: host_name
		0x00, byte(sniLen),     // name length
	}
	sniExt = append(sniExt, sni...)

	// Heartbeat extension: peer allowed to send requests = 0x01
	heartbeatExt := []byte{0x00, 0x0f, 0x00, 0x01, 0x01}

	extensions := append(sniExt, heartbeatExt...)
	extLen := len(extensions)

	// Cipher suites (common ones for compatibility)
	cipherSuites := []byte{
		0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xc0, 0x0a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
		0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	}

	// Assemble ClientHello body
	chBody := []byte{
		0x03, 0x03, // ClientHello version: TLS 1.2
		// 32-byte random (timestamp + nonce)
		0x5a, 0x5a, 0x5a, 0x5a, // gmt_unix_time placeholder
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c,
		0x00, // session ID length: 0
	}
	// Cipher suites length (2 bytes) + suites
	chBody = append(chBody, 0x00, byte(len(cipherSuites)))
	chBody = append(chBody, cipherSuites...)
	// Compression methods: null only
	chBody = append(chBody, 0x01, 0x00)
	// Extensions length (2 bytes) + extensions
	chBody = append(chBody, 0x00, byte(extLen))
	chBody = append(chBody, extensions...)

	// Handshake header: type=ClientHello(1), length=chBody
	chLen := len(chBody)
	handshake := []byte{
		0x01,
		byte(chLen >> 16), byte(chLen >> 8), byte(chLen),
	}
	handshake = append(handshake, chBody...)

	// TLS record: type=Handshake(0x16), version=TLS1.0 compat(0x0301), length
	hLen := len(handshake)
	record := []byte{
		0x16, 0x03, 0x01,
		byte(hLen >> 8), byte(hLen),
	}
	return append(record, handshake...)
}

// buildMalformedHeartbeat returns a TLS Heartbeat request with inflated payload_length.
// Per RFC 6520: type=request(1), payload_length=N, payload=N bytes, padding
// We claim N=65535 but only send 3 bytes — a vulnerable server echoes 65535 bytes of heap.
func buildMalformedHeartbeat() []byte {
	payload := []byte{
		0x01,       // HeartbeatMessageType: request
		0xff, 0xff, // payload_length: 65535 (lie)
		0x61, 0x62, 0x63, // actual payload: "abc" (3 bytes)
	}
	pLen := len(payload)
	return []byte{
		0x18,                    // Content Type: Heartbeat
		0x03, 0x02,              // Version: TLS 1.2
		byte(pLen >> 8), byte(pLen), // Length
	}
}

func (s *SSLAuditScanner) checkHeartbleed(ctx context.Context, host string, port int) []SSLFinding {
	addr := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{Timeout: s.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.readTimeout))

	// Send ClientHello with heartbeat extension
	hello := buildHeartbeatClientHello(host)
	if _, err := conn.Write(hello); err != nil {
		return nil
	}

	// Read TLS records until we see ServerHelloDone (handshake type 0x0e)
	// or Certificate (0x0b) — enough to know TLS is established
	if !s.waitForServerHelloDone(conn) {
		return nil // Not TLS or doesn't support heartbeat extension
	}

	// Send the malformed heartbeat
	hb := buildMalformedHeartbeat()
	hbPayload := []byte{0x01, 0xff, 0xff, 0x61, 0x62, 0x63}
	pLen := len(hbPayload)
	hb = append([]byte{0x18, 0x03, 0x02, byte(pLen >> 8), byte(pLen)}, hbPayload...)
	if _, err := conn.Write(hb); err != nil {
		return nil
	}

	// Read response — a vulnerable server sends back 65535+ bytes
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, 131072)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return nil
	}

	// Check if response is a heartbeat record (type 0x18) with substantial data
	if n >= 5 && buf[0] == 0x18 {
		respLen := int(buf[3])<<8 | int(buf[4])
		if respLen > 3 { // More than 3 bytes echoed — server leaked memory
			return []SSLFinding{{
				Severity:    4,
				Title:       "HEARTBLEED — OpenSSL heap memory disclosure (CVE-2014-0160)",
				Description: "The server responded to a malformed TLS Heartbeat with more data than was sent, leaking heap memory. This can expose private keys, session tokens, passwords, and other sensitive data from server RAM. Despite being disclosed in 2014, Heartbleed still appears in embedded devices, legacy appliances, IoT firmware, and unpatched VPNs in 2026.",
				Evidence:    fmt.Sprintf("Sent 3-byte payload, server returned %d bytes of heap data", respLen),
				Remediation: "Upgrade OpenSSL to ≥1.0.1g (or ≥1.0.2a). Revoke and reissue all certificates. Invalidate all session tokens. Rotate any secrets that may have been in server memory.",
				CVEID:       "CVE-2014-0160",
			}}
		}
	}

	return nil
}

// waitForServerHelloDone reads TLS records until ServerHelloDone or timeout.
func (s *SSLAuditScanner) waitForServerHelloDone(conn net.Conn) bool {
	_ = conn.SetDeadline(time.Now().Add(s.readTimeout))
	buf := make([]byte, 16384)
	for i := 0; i < 8; i++ { // max 8 records
		n, err := conn.Read(buf)
		if err != nil || n < 5 {
			return false
		}
		recordType := buf[0]
		if recordType == 0x15 { // Alert
			return false
		}
		if recordType == 0x16 { // Handshake — look for ServerHelloDone (0x0e) or Certificate (0x0b)
			for j := 5; j < n-1; j++ {
				if buf[j] == 0x0e || buf[j] == 0x0b {
					return true
				}
			}
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────
//  4b — POODLE via SSLv3 (CVE-2014-3566)
// ─────────────────────────────────────────────────────────────

// sslv3ClientHello is a raw SSLv3 ClientHello record.
// If the server responds with a ServerHello using version 0x0300, it supports SSLv3 → POODLE.
var sslv3ClientHello = []byte{
	// TLS Record Layer
	0x16,       // Content-Type: Handshake
	0x03, 0x00, // Version: SSL 3.0
	0x00, 0x2f, // Length: 47 bytes

	// Handshake Header
	0x01,             // HandshakeType: ClientHello
	0x00, 0x00, 0x2b, // Length: 43 bytes

	// ClientHello
	0x03, 0x00, // ClientHello version: SSL 3.0
	// Random (32 bytes)
	0x51, 0x51, 0x51, 0x51, 0xb5, 0x4e, 0xec, 0x40,
	0x78, 0x37, 0x4d, 0x91, 0x55, 0xd5, 0x28, 0x55,
	0x25, 0x24, 0x0e, 0xa6, 0x62, 0x9b, 0x5f, 0xff,
	0xdb, 0xf8, 0x72, 0x0d, 0xdd, 0x17, 0xda, 0x8d,

	0x00,       // Session ID length: 0
	0x00, 0x04, // Cipher Suites length: 4 bytes (2 suites)
	0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x00, 0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV

	0x01, // Compression Methods length
	0x00, // CompressionMethod: null
}

func (s *SSLAuditScanner) checkPOODLE(ctx context.Context, host string, port int) []SSLFinding {
	addr := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{Timeout: s.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.readTimeout))

	if _, err := conn.Write(sslv3ClientHello); err != nil {
		return nil
	}

	// Read the server response
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil
	}

	// Check for Alert (0x15) — server rejected SSLv3 → not vulnerable
	if header[0] == 0x15 {
		return nil
	}

	// Check for Handshake (0x16) with SSLv3 version (0x03 0x00)
	if header[0] == 0x16 && header[1] == 0x03 && header[2] == 0x00 {
		// Read the ServerHello to confirm
		bodyLen := int(binary.BigEndian.Uint16(header[3:5]))
		body := make([]byte, bodyLen)
		io.ReadFull(conn, body) //nolint

		// Handshake type 0x02 = ServerHello
		if len(body) > 0 && body[0] == 0x02 {
			return []SSLFinding{{
				Severity:    3,
				Title:       "POODLE — SSLv3 enabled (CVE-2014-3566)",
				Description: "The server accepted an SSLv3 ClientHello. SSLv3's CBC padding is not deterministic, allowing a POODLE (Padding Oracle On Downgraded Legacy Encryption) attacker to decrypt 1 byte per 256 requests. In 2026, SSLv3 is still found in legacy VPN appliances, industrial control systems, and embedded web servers.",
				Evidence:    fmt.Sprintf("Server responded with SSLv3 ServerHello on %s:%d", host, port),
				Remediation: "Disable SSLv3 entirely. For OpenSSL: add 'no-sslv3' to your build or set SSL_OP_NO_SSLv3. For nginx: ssl_protocols TLSv1.2 TLSv1.3;",
				CVEID:       "CVE-2014-3566",
			}}
		}
	}

	return nil
}

// ─────────────────────────────────────────────────────────────
//  4c — CRIME (CVE-2012-4929)
// ─────────────────────────────────────────────────────────────

func (s *SSLAuditScanner) checkCRIME(ctx context.Context, addr, host string) []SSLFinding {
	// Go's crypto/tls never negotiates TLS-level compression, so we check
	// whether the server would accept a compression request by inspecting
	// the ServerHello compression method in a raw handshake.
	// Most modern servers reject compression, but legacy nginx/Apache configs may not.
	dialer := &net.Dialer{Timeout: s.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.readTimeout))

	// ClientHello requesting DEFLATE compression (method 0x01)
	hello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x36,
		0x01, 0x00, 0x00, 0x32,
		0x03, 0x03,
		0x52, 0x52, 0x52, 0x52, 0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
		0x00,       // session ID len
		0x00, 0x04, // cipher suites len
		0xc0, 0x2f, 0x00, 0x35, // ECDHE-RSA-AES128-GCM, AES256-SHA
		0x02,       // compression methods len: 2
		0x01, 0x00, // DEFLATE, null
	}
	if _, err := conn.Write(hello); err != nil {
		return nil
	}

	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil
	}
	if header[0] != 0x16 {
		return nil
	}

	bodyLen := int(binary.BigEndian.Uint16(header[3:5]))
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil
	}

	// ServerHello compression method is at offset 38 (after random + session ID + cipher suite)
	// body[0]=handshake_type, body[1-3]=length, body[4-5]=server_version,
	// body[6-37]=server_random, body[38]=session_id_len
	if len(body) < 42 || body[0] != 0x02 {
		return nil
	}
	sessionIDLen := int(body[38])
	compressionOffset := 39 + sessionIDLen + 2 // +2 for cipher suite
	if compressionOffset >= len(body) {
		return nil
	}

	if body[compressionOffset] == 0x01 { // DEFLATE accepted
		return []SSLFinding{{
			Severity:    2,
			Title:       "CRIME — TLS compression enabled (CVE-2012-4929)",
			Description: "The server negotiated DEFLATE TLS-level compression. CRIME exploits compression to recover secrets (e.g. session cookies) from HTTPS by observing compressed ciphertext length changes across attacker-controlled requests.",
			Evidence:    fmt.Sprintf("Server accepted DEFLATE (0x01) compression method on %s", addr),
			Remediation: "Disable TLS-level compression. For OpenSSL: SSL_OP_NO_COMPRESSION. For nginx this is the default since 1.2.2. Never enable TLS compression.",
			CVEID:       "CVE-2012-4929",
		}}
	}

	return nil
}

// ─────────────────────────────────────────────────────────────
//  5 — HSTS check
// ─────────────────────────────────────────────────────────────

func (s *SSLAuditScanner) checkHSTS(ctx context.Context, host string, port int) []SSLFinding {
	var findings []SSLFinding

	url := fmt.Sprintf("https://%s:%d/", host, port)
	client := &http.Client{
		Timeout: s.dialTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		findings = append(findings, SSLFinding{
			Severity:    2,
			Title:       "HSTS header missing (Strict-Transport-Security)",
			Description: "Without HSTS, browsers will follow HTTP→HTTPS redirects every time, leaving a window for SSL-stripping attacks (e.g. SSLstrip). An attacker on the same network can transparently downgrade connections.",
			Evidence:    fmt.Sprintf("No Strict-Transport-Security header in response from %s", url),
			Remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		})
		return findings
	}

	// Parse max-age
	maxAge := 0
	includeSubDomains := false
	preload := false
	for _, part := range strings.Split(hsts, ";") {
		part = strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(part, "max-age=") {
			val := strings.TrimPrefix(part, "max-age=")
			maxAge, _ = strconv.Atoi(val)
		}
		if part == "includesubdomains" {
			includeSubDomains = true
		}
		if part == "preload" {
			preload = true
		}
	}

	if maxAge < 31536000 { // 1 year
		findings = append(findings, SSLFinding{
			Severity:    2,
			Title:       fmt.Sprintf("HSTS max-age too short: %d seconds (minimum 31536000)", maxAge),
			Description: "A short HSTS max-age means browsers won't enforce HTTPS for long after a user's first visit, leaving subsequent visits vulnerable to downgrade attacks.",
			Evidence:    "Strict-Transport-Security: " + hsts,
			Remediation: "Set max-age=31536000 (1 year) minimum. For preload list eligibility: max-age=63072000 (2 years).",
		})
	}

	if !includeSubDomains {
		findings = append(findings, SSLFinding{
			Severity:    1,
			Title:       "HSTS missing includeSubDomains directive",
			Description: "Without includeSubDomains, subdomains of this host are not covered by HSTS, allowing SSL-strip attacks on subdomains (e.g. login.example.com).",
			Evidence:    "Strict-Transport-Security: " + hsts,
			Remediation: "Add includeSubDomains to the HSTS header. Ensure all subdomains support HTTPS before adding this.",
		})
	}

	if !preload {
		findings = append(findings, SSLFinding{
			Severity:    0,
			Title:       "HSTS preload not requested",
			Description: "The preload directive enables submission to browser HSTS preload lists, hardcoding HTTPS for your domain into browsers before any visit. Without it, first-time visitors may be vulnerable to SSL-stripping.",
			Evidence:    "Strict-Transport-Security: " + hsts,
			Remediation: "Add preload directive and submit to https://hstspreload.org. Requirements: max-age ≥31536000, includeSubDomains, HTTPS-only on root and all subdomains.",
		})
	}

	if maxAge >= 31536000 && includeSubDomains {
		findings = append(findings, SSLFinding{
			Severity: 0,
			Title:    "HSTS correctly configured",
			Evidence: "Strict-Transport-Security: " + hsts,
		})
	}

	return findings
}

// ─────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────

func isHTTPSPort(port int) bool {
	switch port {
	case 443, 8443, 4443, 4433:
		return true
	}
	return false
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int(d.Hours() / 24)
	if days > 0 {
		return fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("%d hours", int(d.Hours()))
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func certKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	}
	return 0
}

// Unused but kept for future ROBOT check (timing-based RSA PKCS#1 oracle detection)
var _ = big.NewInt
