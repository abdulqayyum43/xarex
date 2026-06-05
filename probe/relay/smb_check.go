// Package relay contains non-destructive checks for common relay-based attack
// primitives: SMB relay and LLMNR/NBT-NS poisoning.
package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/xarex/probe/grpc/pb"
)

const (
	smbPort        = 445
	smbDialTimeout = 5 * time.Second
	smbRWTimeout   = 5 * time.Second

	// SMB2 security mode flags (MS-SMB2 §2.2.4).
	smb2NegotiateSigningEnabled  = 0x01
	smb2NegotiateSigningRequired = 0x02
)

// SMBRelayChecker detects whether SMB signing is required on a host.
// When signing is NOT required the host is susceptible to SMB relay attacks
// (e.g. NTLM relay via Responder + ntlmrelayx).
// This check is entirely non-destructive: it negotiates the SMB2 dialect and
// reads the SecurityMode field from the server's NegotiateResponse, then
// immediately closes the connection.
type SMBRelayChecker struct {
	logger *slog.Logger
}

// NewSMBRelayChecker returns a ready-to-use SMBRelayChecker.
func NewSMBRelayChecker(logger *slog.Logger) *SMBRelayChecker {
	return &SMBRelayChecker{logger: logger}
}

// Check connects to host:445, negotiates SMB2, and inspects the SecurityMode.
// Returns a Finding with severity HIGH if signing is not required.
func (c *SMBRelayChecker) Check(ctx context.Context, host string) (*pb.Finding, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(smbPort))
	c.logger.Info("checking SMB signing", "host", host)

	dialCtx, cancel := context.WithTimeout(ctx, smbDialTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("smb connect %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(smbRWTimeout))

	// 1. Send SMB2 Negotiate Request.
	negReq := buildSMB2NegotiateRequest()
	if _, err := conn.Write(negReq); err != nil {
		return nil, fmt.Errorf("send smb2 negotiate: %w", err)
	}

	// 2. Read the full response (NetBIOS session layer: 4-byte header + payload).
	nbHeader := make([]byte, 4)
	if err := readFull(conn, nbHeader); err != nil {
		return nil, fmt.Errorf("read netbios header: %w", err)
	}
	payloadLen := int(nbHeader[1])<<16 | int(nbHeader[2])<<8 | int(nbHeader[3])
	if payloadLen < 65 || payloadLen > 65536 {
		return nil, fmt.Errorf("unexpected smb2 payload length: %d", payloadLen)
	}

	payload := make([]byte, payloadLen)
	if err := readFull(conn, payload); err != nil {
		return nil, fmt.Errorf("read smb2 response: %w", err)
	}

	// 3. Parse SMB2 header + NegotiateResponse.
	securityMode, dialect, err := parseSMB2NegotiateResponse(payload)
	if err != nil {
		return nil, fmt.Errorf("parse smb2 negotiate response: %w", err)
	}

	signingRequired := (securityMode & smb2NegotiateSigningRequired) != 0
	signingEnabled := (securityMode & smb2NegotiateSigningEnabled) != 0

	c.logger.Info("SMB2 negotiate result",
		"host", host,
		"dialect", fmt.Sprintf("0x%04x", dialect),
		"security_mode", fmt.Sprintf("0x%02x", securityMode),
		"signing_required", signingRequired,
		"signing_enabled", signingEnabled,
	)

	finding := &pb.Finding{
		FindingId: uuid.NewString(),
		Host:      host,
		Port:      int32(smbPort),
		Protocol:  "tcp",
		Service:   "smb2",
		Timestamp: time.Now().UnixMilli(),
		Metadata: map[string]string{
			"dialect":          fmt.Sprintf("0x%04x", dialect),
			"security_mode":    fmt.Sprintf("0x%02x", securityMode),
			"signing_enabled":  strconv.FormatBool(signingEnabled),
			"signing_required": strconv.FormatBool(signingRequired),
		},
	}

	if !signingRequired {
		finding.Severity = pb.Severity_HIGH
		finding.Title = "SMB Signing Not Required"
		finding.Description = fmt.Sprintf(
			"Host %s (SMB2 dialect 0x%04x) does not require message signing "+
				"(SecurityMode=0x%02x). An attacker on the same network segment can "+
				"relay NTLM authentication to this host.",
			host, dialect, securityMode,
		)
		finding.Evidence = fmt.Sprintf(
			"SMB2 NegotiateResponse SecurityMode=0x%02x — "+
				"SMB2_NEGOTIATE_SIGNING_REQUIRED bit is NOT set.",
			securityMode,
		)
		finding.Remediation = "Enable and enforce SMB signing via Group Policy: " +
			"Computer Configuration → Windows Settings → Security Settings → " +
			"Local Policies → Security Options → " +
			"\"Microsoft network server: Digitally sign communications (always)\" = Enabled."
		finding.CveId = "CVE-2017-0143" // EternalBlue / SMB relay class
	} else {
		finding.Severity = pb.Severity_INFO
		finding.Title = "SMB Signing Required"
		finding.Description = fmt.Sprintf(
			"Host %s requires SMB message signing (SecurityMode=0x%02x). "+
				"SMB relay attacks are not directly applicable.",
			host, securityMode,
		)
		finding.Evidence = fmt.Sprintf(
			"SMB2 NegotiateResponse SecurityMode=0x%02x — "+
				"SMB2_NEGOTIATE_SIGNING_REQUIRED bit is SET.",
			securityMode,
		)
	}

	return finding, nil
}

// ─────────────────────────────────────────────
//  SMB2 packet construction
// ─────────────────────────────────────────────

// buildSMB2NegotiateRequest constructs a minimal SMB2 NEGOTIATE request wrapped
// in a NetBIOS Session Service (NBSS) header.
//
// References:
//   - MS-SMB2 §2.2.3  – NEGOTIATE Request
//   - MS-SMB2 §2.1    – SMB2 Header
func buildSMB2NegotiateRequest() []byte {
	// SMB2 header (64 bytes).
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xFE, 'S', 'M', 'B'}) // ProtocolId
	binary.LittleEndian.PutUint16(hdr[4:], 64)   // StructureSize
	binary.LittleEndian.PutUint16(hdr[6:], 0)    // CreditCharge
	binary.LittleEndian.PutUint32(hdr[8:], 0)    // Status
	binary.LittleEndian.PutUint16(hdr[12:], 0)   // Command = NEGOTIATE (0)
	binary.LittleEndian.PutUint16(hdr[14:], 126) // CreditRequest
	binary.LittleEndian.PutUint32(hdr[16:], 0)   // Flags
	binary.LittleEndian.PutUint32(hdr[20:], 0)   // NextCommand
	binary.LittleEndian.PutUint64(hdr[24:], 0)   // MessageId
	binary.LittleEndian.PutUint32(hdr[32:], 0)   // Reserved
	binary.LittleEndian.PutUint32(hdr[36:], 0)   // TreeId
	binary.LittleEndian.PutUint64(hdr[40:], 0)   // SessionId
	// Signature (16 bytes at offset 48): all zeros for unsigned.

	// NEGOTIATE request body.
	// Dialects: 0x0202 (SMB 2.0.2), 0x0210 (SMB 2.1), 0x0300 (SMB 3.0), 0x0302 (SMB 3.0.2), 0x0311 (SMB 3.1.1).
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}
	dialectCount := len(dialects)

	body := make([]byte, 36+dialectCount*2)
	binary.LittleEndian.PutUint16(body[0:], 36)               // StructureSize
	binary.LittleEndian.PutUint16(body[2:], uint16(dialectCount)) // DialectCount
	binary.LittleEndian.PutUint16(body[4:], 1)                // SecurityMode (signing enabled)
	binary.LittleEndian.PutUint16(body[6:], 0)                // Reserved
	binary.LittleEndian.PutUint32(body[8:], 0x7fc0ff21)       // Capabilities
	// ClientGuid (16 bytes at offset 12): use a fixed probe GUID.
	copy(body[12:28], []byte{
		0x50, 0x68, 0x61, 0x6e, 0x74, 0x6f, 0x6d, 0x2d,
		0x70, 0x72, 0x6f, 0x62, 0x65, 0x00, 0x00, 0x01,
	})
	binary.LittleEndian.PutUint64(body[28:], 0) // ClientStartTime
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+i*2:], d)
	}

	smb2Msg := append(hdr, body...)

	// NetBIOS Session Service header (4 bytes): type=0x00, length=3-byte big-endian.
	msgLen := len(smb2Msg)
	nbss := []byte{
		0x00,
		byte(msgLen >> 16),
		byte(msgLen >> 8),
		byte(msgLen),
	}
	return append(nbss, smb2Msg...)
}

// parseSMB2NegotiateResponse parses the server's NegotiateResponse payload
// (without the 4-byte NBSS header) and returns the SecurityMode and selected dialect.
func parseSMB2NegotiateResponse(payload []byte) (securityMode uint8, dialect uint16, err error) {
	// Minimum: 64-byte SMB2 header + 65-byte NEGOTIATE Response body = 129.
	if len(payload) < 65 {
		return 0, 0, fmt.Errorf("payload too short: %d bytes", len(payload))
	}

	// Verify ProtocolId.
	if string(payload[0:4]) != "\xFESMB" {
		return 0, 0, fmt.Errorf("not an SMB2 response: %x", payload[0:4])
	}

	// SMB2 command at offset 12 (little-endian): 0x0000 = NEGOTIATE.
	cmd := binary.LittleEndian.Uint16(payload[12:14])
	if cmd != 0x0000 {
		return 0, 0, fmt.Errorf("unexpected SMB2 command: 0x%04x", cmd)
	}

	// NegotiateResponse starts at offset 64 (after the 64-byte header).
	resp := payload[64:]
	if len(resp) < 65 {
		return 0, 0, fmt.Errorf("negotiate response body too short: %d", len(resp))
	}

	// SecurityMode is at offset 2 of the response body (byte).
	securityMode = resp[2]
	// DialectRevision is at offset 4.
	dialect = binary.LittleEndian.Uint16(resp[4:6])
	return securityMode, dialect, nil
}

// readFull is a thin wrapper around io.ReadFull that returns a typed error.
func readFull(conn net.Conn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return err
		}
	}
	return nil
}
