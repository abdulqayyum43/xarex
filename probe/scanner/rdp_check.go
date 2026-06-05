// Package scanner — RDP Security Checker (task type 15)
//
// Assesses security configuration of Remote Desktop Protocol (RDP) on port 3389.
//
// Checks performed:
//
//  1. NLA (Network Level Authentication) — Is CredSSP/NLA required?
//     If not, RDP accepts connections before authentication, enabling:
//     - Unauthenticated memory exposure (BlueKeep surface)
//     - Denial of service via connection exhaustion
//     - Credential brute-force without rate limiting at the session layer
//
//  2. Encryption level — Does the server negotiate TLS, or fall back to
//     legacy RC4-based RDP encryption (PROTOCOL_RDP)? Legacy encryption
//     is trivially breakable and enables MitM credential capture.
//
//  3. BlueKeep / CVE-2019-0708 attack surface — RDP exposed without NLA
//     on Windows systems is the BlueKeep threat model. We flag the attack
//     surface conservatively (no exploitation) so blue teams can prioritise.
//
// Protocol reference: [MS-RDPBCGR] — RDP Basic Connectivity and Graphics Remoting.
// The X.224 Connection Request PDU is the very first message in the RDP handshake.
package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xarex/probe/grpc/pb"
)

// RDPChecker assesses RDP security configuration on port 3389.
type RDPChecker struct {
	logger  *slog.Logger
	timeout time.Duration
}

// NewRDPChecker creates a new RDPChecker.
func NewRDPChecker(logger *slog.Logger) *RDPChecker {
	return &RDPChecker{
		logger:  logger,
		timeout: 10 * time.Second,
	}
}

// rdpNegotiationProtocol flags from the X.224 Connection Confirm response.
const (
	rdpProtocolRDP       = 0x00000000 // Legacy RDP encryption
	rdpProtocolSSL       = 0x00000001 // TLS
	rdpProtocolHybrid    = 0x00000002 // CredSSP (NLA)
	rdpProtocolRDSTLS    = 0x00000004 // RDSTLS
	rdpProtocolHybridEx  = 0x00000008 // CredSSP with Early User Authorization
)

// Check performs all RDP security checks against host:3389.
func (r *RDPChecker) Check(ctx context.Context, host string) ([]*pb.Finding, error) {
	negotiation, rawResponse, connErr := r.sendConnectionRequest(ctx, host, 3389)
	if connErr != nil {
		r.logger.Debug("rdp not available", "host", host, "error", connErr)
		return nil, nil // Port not open or not RDP
	}

	var findings []*pb.Finding

	// ── Check 1: NLA / CredSSP requirement ──────────────────────────────────
	nlaRequired := negotiation&rdpProtocolHybrid != 0 || negotiation&rdpProtocolHybridEx != 0
	tlsSupported := negotiation&rdpProtocolSSL != 0 || nlaRequired
	legacyOnly := negotiation == rdpProtocolRDP

	if !nlaRequired {
		// NLA is not required — HIGH severity.
		severity := pb.Severity_HIGH
		desc := fmt.Sprintf(
			"RDP on %s:3389 does not require Network Level Authentication (NLA/CredSSP). "+
				"Without NLA, the server presents the Windows login screen before authentication, "+
				"exposing it to:\n"+
				"  - Brute-force attacks without rate limiting at the session layer\n"+
				"  - Denial of service by consuming terminal server sessions\n"+
				"  - Attack surface for unauthenticated pre-auth vulnerabilities (CVE-2019-0708 model)\n"+
				"Negotiated protocol flags: 0x%08X",
			host, negotiation)

		findings = append(findings, &pb.Finding{
			FindingId: uuid.NewString(),
			Host:      host,
			Port:      3389,
			Protocol:  "tcp",
			Service:   "rdp",
			Severity:  severity,
			Title:     "RDP: Network Level Authentication (NLA) Not Required",
			Description: desc,
			Evidence: fmt.Sprintf(
				"Host: %s:3389\nX.224 Connection Confirm received.\n"+
					"Selected security protocol: 0x%08X\nNLA/CredSSP required: false\n\n"+
					"Raw X.224 CC PDU (hex):\n%s",
				host, negotiation, formatHex(rawResponse)),
			Remediation: "Enable Network Level Authentication in Windows:\n" +
				"  System Properties → Remote → Remote Desktop → 'Allow connections only from computers running Remote Desktop with Network Level Authentication'\n" +
				"  Group Policy: Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → " +
				"'Require user authentication for remote connections by using Network Level Authentication' → Enabled",
			CveId: "CVE-2019-0708",
			Metadata: map[string]string{
				"nla_required":     "false",
				"protocol_flags":   fmt.Sprintf("0x%08X", negotiation),
				"tls_supported":    fmt.Sprintf("%t", tlsSupported),
				"legacy_rdp_only":  fmt.Sprintf("%t", legacyOnly),
			},
			Timestamp: time.Now().UnixMilli(),
		})
	}

	// ── Check 2: Legacy RDP Encryption (no TLS) ─────────────────────────────
	if legacyOnly {
		findings = append(findings, &pb.Finding{
			FindingId: uuid.NewString(),
			Host:      host,
			Port:      3389,
			Protocol:  "tcp",
			Service:   "rdp",
			Severity:  pb.Severity_HIGH,
			Title:     "RDP: Legacy RC4 Encryption (No TLS)",
			Description: fmt.Sprintf(
				"The RDP server at %s:3389 negotiated legacy RDP protocol encryption (PROTOCOL_RDP = 0x00000000) "+
					"instead of TLS. Legacy RDP encryption uses RC4 which is cryptographically broken. "+
					"A network-positioned attacker can:\n"+
					"  - Perform Man-in-the-Middle attacks to capture credentials\n"+
					"  - Decrypt session traffic using known RC4 weaknesses\n"+
					"  - Inject arbitrary keystrokes into the RDP session",
				host),
			Evidence: fmt.Sprintf(
				"Host: %s:3389\nNegotiated protocol: PROTOCOL_RDP (legacy RC4 encryption)\n"+
					"Protocol flags: 0x%08X\n\nRaw response:\n%s",
				host, negotiation, formatHex(rawResponse)),
			Remediation: "Require TLS for RDP connections:\n" +
				"  Group Policy: Computer Configuration → Administrative Templates → Windows Components → " +
				"Remote Desktop Services → RDP Security Layer → 'SSL (TLS 1.0)' or 'Negotiate'\n" +
				"  For highest security: Enable NLA which implicitly requires TLS.",
			Metadata: map[string]string{
				"protocol_flags":  fmt.Sprintf("0x%08X", negotiation),
				"encryption_type": "Legacy RC4 (PROTOCOL_RDP)",
			},
			Timestamp: time.Now().UnixMilli(),
		})
	}

	// ── Check 3: BlueKeep Attack Surface ────────────────────────────────────
	// BlueKeep (CVE-2019-0708) affects RDP without NLA on Windows 7/2008/XP/2003.
	// We don't need to exploit it — the attack surface is flagged whenever NLA
	// is absent, since the pre-auth exposure is the vulnerability model.
	if !nlaRequired {
		findings = append(findings, &pb.Finding{
			FindingId: uuid.NewString(),
			Host:      host,
			Port:      3389,
			Protocol:  "tcp",
			Service:   "rdp",
			Severity:  pb.Severity_CRITICAL,
			CveId:     "CVE-2019-0708",
			Title:     "RDP: BlueKeep Attack Surface Exposed (CVE-2019-0708)",
			Description: fmt.Sprintf(
				"RDP on %s:3389 is exposed without Network Level Authentication, matching the threat model "+
					"for CVE-2019-0708 (BlueKeep) and its variants (CVE-2019-1181, CVE-2019-1182 — DejaBlue). "+
					"BlueKeep is a pre-authentication, wormable Remote Code Execution vulnerability in Windows "+
					"Remote Desktop Services affecting:\n"+
					"  - Windows 7 SP1 / Windows Server 2008 R2\n"+
					"  - Windows Server 2008 SP2\n"+
					"  - Windows XP (end-of-life)\n"+
					"  - Windows Server 2003 (end-of-life)\n\n"+
					"NLA-disabled RDP accepts connections before user authentication, allowing the use-after-free "+
					"vulnerability in rdpdr.sys to be triggered by unauthenticated remote attackers.\n\n"+
					"NOTE: This is an attack surface assessment — actual exploitation was NOT attempted. "+
					"Patch status should be verified via authenticated OS version enumeration.",
				host),
			Evidence: fmt.Sprintf(
				"Host: %s:3389\nRDP is accessible without pre-authentication NLA requirement.\n"+
					"Protocol flags: 0x%08X\n"+
					"Attack surface: Pre-authentication RDP connection accepted.\n\n"+
					"CVE-2019-0708 threat model conditions met:\n"+
					"  [✓] RDP port 3389 open\n"+
					"  [✓] NLA not required (pre-auth exposure)\n"+
					"  [?] Windows version: requires OS fingerprinting to confirm\n\n"+
					"CVSS v3.1 Base Score: 9.8 (Critical)\n"+
					"CVSS Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				host, negotiation),
			Remediation: "Immediate actions:\n" +
				"1. Apply Microsoft security updates (MS19-0708 / KB4499175, KB4499180, KB4500331)\n" +
				"2. Enable Network Level Authentication to prevent unauthenticated connections\n" +
				"3. Block RDP (TCP 3389) from the internet; use VPN or jump server for remote access\n" +
				"4. Enable Windows Firewall rules to restrict RDP source addresses\n" +
				"5. Disable RDP entirely if not needed\n" +
				"References: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",
			Metadata: map[string]string{
				"cve":              "CVE-2019-0708",
				"cvss_score":       "9.8",
				"nla_required":     "false",
				"protocol_flags":   fmt.Sprintf("0x%08X", negotiation),
				"attack_surface":   "pre-auth-rce",
				"exploitation_attempted": "false",
			},
			Timestamp: time.Now().UnixMilli(),
		})
	}

	r.logger.Info("rdp security check complete",
		"host", host,
		"nla_required", nlaRequired,
		"tls_supported", tlsSupported,
		"legacy_only", legacyOnly,
		"findings", len(findings),
	)

	return findings, nil
}

// sendConnectionRequest sends an RDP X.224 Connection Request PDU and parses
// the X.224 Connection Confirm response to determine the negotiated security protocol.
//
// RDP Connection Initiation sequence ([MS-RDPBCGR] §1.3.1.1):
//
//	Client → Server: TPKT + X.224 Connection Request (CR) PDU with NegoRequest
//	Server → Client: TPKT + X.224 Connection Confirm (CC) PDU with NegoResponse
func (r *RDPChecker) sendConnectionRequest(ctx context.Context, host string, port int) (protocol uint32, raw []byte, err error) {
	dialCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	d := &net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return 0, nil, fmt.Errorf("dial %s:%d: %w", host, port, err)
	}
	defer conn.Close() //nolint:errcheck
	conn.SetDeadline(time.Now().Add(r.timeout)) //nolint:errcheck

	// Build X.224 CR PDU with RDP Negotiation Request.
	// Requests all protocols: RDP (0), SSL/TLS (1), CredSSP/NLA (2).
	crPDU := buildRDPConnectionRequest()

	if _, err = conn.Write(crPDU); err != nil {
		return 0, nil, fmt.Errorf("write cr pdu: %w", err)
	}

	// Read TPKT header (4 bytes).
	tpktHeader := make([]byte, 4)
	if err = readFull(conn, tpktHeader); err != nil {
		return 0, nil, fmt.Errorf("read tpkt header: %w", err)
	}

	// Validate TPKT version (must be 3).
	if tpktHeader[0] != 0x03 {
		return 0, nil, fmt.Errorf("not a TPKT packet (version=%d)", tpktHeader[0])
	}

	// Total TPKT length (includes the 4-byte header itself).
	totalLen := int(binary.BigEndian.Uint16(tpktHeader[2:4]))
	if totalLen < 4 || totalLen > 1024 {
		return 0, nil, fmt.Errorf("invalid TPKT length: %d", totalLen)
	}

	// Read the rest of the TPKT payload.
	payload := make([]byte, totalLen-4)
	if err = readFull(conn, payload); err != nil {
		return 0, nil, fmt.Errorf("read tpkt payload: %w", err)
	}

	raw = append(tpktHeader, payload...)

	// Parse X.224 Connection Confirm PDU.
	// X.224 header: length(1) + type(1) + DST-REF(2) + SRC-REF(2) + CLASS(1) = 7 bytes
	if len(payload) < 7 {
		return 0, raw, fmt.Errorf("payload too short for X.224 (%d bytes)", len(payload))
	}

	// X.224 PDU type 0xD0 = Connection Confirm (CC)
	x224Type := payload[1]
	if x224Type != 0xD0 {
		return 0, raw, fmt.Errorf("expected X.224 CC (0xD0), got 0x%02X", x224Type)
	}

	// RDP Negotiation Response follows immediately after the 7-byte X.224 header.
	if len(payload) < 7+8 {
		// Server sent CC without negotiation response — implies legacy RDP only.
		r.logger.Debug("rdp server sent CC without negotiation response (legacy mode)", "host", host)
		return rdpProtocolRDP, raw, nil
	}

	negoResp := payload[7:]
	negoType := negoResp[0]

	switch negoType {
	case 0x02: // TYPE_RDP_NEG_RSP
		if len(negoResp) < 8 {
			return rdpProtocolRDP, raw, nil
		}
		// Flags at offset 1 (1 byte), Length at 2 (2 bytes), selectedProtocol at 4 (4 bytes).
		selectedProtocol := binary.LittleEndian.Uint32(negoResp[4:8])
		return selectedProtocol, raw, nil

	case 0x03: // TYPE_RDP_NEG_FAILURE
		if len(negoResp) >= 8 {
			failCode := binary.LittleEndian.Uint32(negoResp[4:8])
			r.logger.Debug("rdp negotiation failure", "host", host, "fail_code", failCode)
		}
		// Failure response means server cannot satisfy our protocol request.
		// This often means legacy-only. Return that.
		return rdpProtocolRDP, raw, nil

	default:
		// Unknown negotiation response — still got a CC, so RDP is running.
		return rdpProtocolRDP, raw, nil
	}
}

// buildRDPConnectionRequest builds a minimal TPKT + X.224 CR PDU with RDP Neg Request.
//
// Reference: [MS-RDPBCGR] §2.2.1.1 — Client X.224 Connection Request PDU
func buildRDPConnectionRequest() []byte {
	// RDP Negotiation Request ([MS-RDPBCGR] §2.2.1.1.1)
	// type=0x01 (TYPE_RDP_NEG_REQ), flags=0x00, length=0x0008,
	// requestedProtocols = PROTOCOL_RDP|PROTOCOL_SSL|PROTOCOL_HYBRID = 0x00000003
	negoReq := []byte{
		0x01,       // type: TYPE_RDP_NEG_REQ
		0x00,       // flags
		0x08, 0x00, // length: 8 bytes (little-endian)
		0x03, 0x00, 0x00, 0x00, // requestedProtocols: RDP + SSL + Hybrid/NLA
	}

	// X.224 Connection Request (CR) PDU
	// Cookie + negotiation request form the variable data.
	cookie := []byte("Cookie: mstshash=XarexProbe\r\n")
	varData := append(cookie, negoReq...)

	// X.224 length = 6 + len(varData) (length excludes the length byte itself in COTP)
	x224Len := byte(6 + len(varData))
	x224 := []byte{
		x224Len,    // LI: length indicator
		0xE0,       // PDU type: CR (Connection Request)
		0x00, 0x00, // DST-REF
		0x00, 0x00, // SRC-REF
		0x00,       // CLASS (0)
	}
	x224 = append(x224, varData...)

	// TPKT header: version=3, reserved=0, length (big-endian, includes 4-byte header)
	tpktLen := uint16(4 + len(x224))
	tpkt := []byte{
		0x03,                    // version
		0x00,                    // reserved
		byte(tpktLen >> 8),      // length high byte
		byte(tpktLen & 0xFF),    // length low byte
	}

	return append(tpkt, x224...)
}

// formatHex returns a hex dump of up to 64 bytes with space-separated octets.
func formatHex(data []byte) string {
	if len(data) > 64 {
		data = data[:64]
	}
	var sb strings.Builder
	for i, b := range data {
		if i > 0 && i%16 == 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(&sb, "%02X ", b)
	}
	return strings.TrimRight(sb.String(), " ")
}
