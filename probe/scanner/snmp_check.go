// Package scanner — SNMP Community String Checker (task type 14)
//
// Tests SNMP v1/v2c implementations with common community strings on UDP port 161.
// SNMPv1/v2c uses cleartext community strings as the only form of authentication.
// A guessable community string allows an attacker to:
//
//   - Enumerate network topology (interfaces, routing tables, ARP caches)
//   - Extract device configuration (running-config on Cisco via SNMP write)
//   - Identify software versions for targeted exploitation
//   - In RW community: modify device configuration remotely
//
// Implementation note: We build a minimal SNMPv1 GET PDU by hand using
// BER-encoded ASN.1, avoiding any external SNMP library dependency.
// The sysDescr OID (1.3.6.1.2.1.1.1.0) is universally supported and
// its response unambiguously confirms a working community string.
package scanner

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xarex/probe/grpc/pb"
)

// SNMPChecker tests SNMP v1/v2c community strings via raw UDP PDUs.
type SNMPChecker struct {
	logger  *slog.Logger
	timeout time.Duration
}

// NewSNMPChecker creates a new SNMPChecker.
func NewSNMPChecker(logger *slog.Logger) *SNMPChecker {
	return &SNMPChecker{
		logger:  logger,
		timeout: 3 * time.Second,
	}
}

// snmpCommunities is the list of common SNMP community strings to test.
var snmpCommunities = []string{
	"public",
	"private",
	"community",
	"admin",
	"manager",
	"snmp",
	"cisco",
	"default",
	"monitor",
	"write",
	"read",
	"secret",
	"guest",
	"internal",
	"network",
	"all",
	"test",
}

// Check tests common SNMP community strings against host on UDP port 161.
func (s *SNMPChecker) Check(ctx context.Context, host string) ([]*pb.Finding, error) {
	var findings []*pb.Finding

	for _, community := range snmpCommunities {
		// Check context before each attempt.
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		sysDescr, version, err := s.probeSNMP(ctx, host, 161, community)
		if err != nil {
			s.logger.Debug("snmp probe failed",
				"host", host, "community", community, "error", err)
			continue
		}

		s.logger.Warn("SNMP community string accepted",
			"host", host, "community", community, "version", version)

		findings = append(findings, &pb.Finding{
			FindingId: uuid.NewString(),
			Host:      host,
			Port:      161,
			Protocol:  "udp",
			Service:   "snmp",
			Severity:  pb.Severity_HIGH,
			Title:     fmt.Sprintf("SNMP Community String Accepted: %q (%s)", community, version),
			Description: fmt.Sprintf(
				"SNMP %s is running on %s:161 and accepts the community string %q. "+
					"This allows unauthenticated read access to the Management Information Base (MIB), "+
					"which includes network topology, interface configuration, routing tables, ARP caches, "+
					"and device software versions. In some configurations, write communities also exist "+
					"that allow remote configuration modification.",
				version, host, community),
			Evidence: fmt.Sprintf(
				"Host: %s:161/udp\nProtocol: %s\nCommunity: %q\n\n"+
					"sysDescr (OID 1.3.6.1.2.1.1.1.0):\n%s",
				host, version, community, sysDescr),
			Remediation: "1. Upgrade to SNMPv3 which supports authentication (MD5/SHA) and encryption (DES/AES). " +
				"2. If SNMPv1/v2c must be used, change community strings to complex random values. " +
				"3. Implement ACLs to restrict SNMP access to authorised management stations only. " +
				"4. Disable SNMP entirely if not required. " +
				"5. Use firewall rules to block UDP port 161 from external networks.",
			Metadata: map[string]string{
				"community":   community,
				"snmp_version": version,
				"oid":         "1.3.6.1.2.1.1.1.0",
				"sys_descr":   truncateSNMP(sysDescr, 200),
				"port":        "161",
			},
			Timestamp: time.Now().UnixMilli(),
		})
	}

	return findings, nil
}

// probeSNMP sends an SNMPv1 GET for sysDescr and returns the value and SNMP version string.
// Returns an error if no valid GetResponse is received.
func (s *SNMPChecker) probeSNMP(ctx context.Context, host string, port int, community string) (sysDescr, version string, err error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	conn, dialErr := net.DialTimeout("udp", addr, s.timeout)
	if dialErr != nil {
		return "", "", fmt.Errorf("dial udp %s: %w", addr, dialErr)
	}
	defer conn.Close() //nolint:errcheck

	deadline := time.Now().Add(s.timeout)
	conn.SetDeadline(deadline) //nolint:errcheck

	// Build SNMPv1 GET request for sysDescr OID.
	requestID := int32(0x1234ABCD)
	pdu := buildSNMPv1Get(community, requestID)

	if _, err = conn.Write(pdu); err != nil {
		return "", "", fmt.Errorf("write snmp pdu: %w", err)
	}

	// Read response.
	buf := make([]byte, 4096)
	n, readErr := conn.Read(buf)
	if readErr != nil {
		return "", "", fmt.Errorf("read snmp response: %w", readErr)
	}

	// Parse the response to confirm community string was accepted.
	descr, ver, parseErr := parseSNMPResponse(buf[:n])
	if parseErr != nil {
		return "", "", fmt.Errorf("parse snmp response: %w", parseErr)
	}

	return descr, ver, nil
}

// buildSNMPv1Get constructs a minimal SNMPv1 GET request PDU using BER encoding.
//
// ASN.1 structure:
//
//	SEQUENCE {
//	  INTEGER 0                         -- version (v1=0, v2c=1)
//	  OCTET STRING community
//	  GetRequest-PDU [0] {
//	    INTEGER request-id
//	    INTEGER error-status (0)
//	    INTEGER error-index  (0)
//	    VarBindList SEQUENCE {
//	      VarBind SEQUENCE {
//	        OID 1.3.6.1.2.1.1.1.0       -- sysDescr
//	        NULL
//	      }
//	    }
//	  }
//	}
func buildSNMPv1Get(community string, requestID int32) []byte {
	// sysDescr OID: 1.3.6.1.2.1.1.1.0
	oid := encodeOID([]uint32{1, 3, 6, 1, 2, 1, 1, 1, 0})

	// VarBind: SEQUENCE { OID, NULL }
	varBind := berSequence(append(
		berOID(oid),
		berNull()...,
	))

	// VarBindList: SEQUENCE { VarBind }
	varBindList := berSequence(varBind)

	// GetRequest-PDU: [0] IMPLICIT SEQUENCE { req-id, err-status, err-index, VarBindList }
	pduContents := concat(
		berInt(int64(requestID)),
		berInt(0),   // error-status
		berInt(0),   // error-index
		varBindList,
	)
	getPDU := berTagged(0xA0, pduContents) // context [0]

	// SNMP Message: SEQUENCE { version(int), community(oct-str), pdu }
	msg := berSequence(concat(
		berInt(0),                        // SNMPv1 version = 0
		berOctetString([]byte(community)),
		getPDU,
	))

	return msg
}

// parseSNMPResponse parses a raw SNMP response UDP datagram.
// Returns the sysDescr string value and the SNMP version string.
// Returns an error if the message is not a valid GetResponse for our request.
func parseSNMPResponse(data []byte) (sysDescr, version string, err error) {
	if len(data) < 2 {
		return "", "", fmt.Errorf("response too short")
	}

	// Outer SEQUENCE
	if data[0] != 0x30 {
		return "", "", fmt.Errorf("not a SEQUENCE (tag=0x%02X)", data[0])
	}
	offset := 2
	if data[1]&0x80 != 0 { // long form length
		numBytes := int(data[1] & 0x7F)
		offset += numBytes
	}
	if offset >= len(data) {
		return "", "", fmt.Errorf("message truncated at outer sequence")
	}

	// Version INTEGER
	if offset+2 >= len(data) || data[offset] != 0x02 {
		return "", "", fmt.Errorf("expected INTEGER for version")
	}
	versionLen := int(data[offset+1])
	if offset+2+versionLen > len(data) {
		return "", "", fmt.Errorf("version field truncated")
	}
	ver := 0
	for i := 0; i < versionLen; i++ {
		ver = (ver << 8) | int(data[offset+2+i])
	}
	switch ver {
	case 0:
		version = "SNMPv1"
	case 1:
		version = "SNMPv2c"
	default:
		version = fmt.Sprintf("SNMPv%d", ver+1)
	}
	offset += 2 + versionLen

	// Community STRING
	if offset+2 >= len(data) || data[offset] != 0x04 {
		return "", "", fmt.Errorf("expected OCTET STRING for community")
	}
	communityLen := int(data[offset+1])
	offset += 2 + communityLen

	// PDU — must be GetResponse (0xA2)
	if offset >= len(data) {
		return "", "", fmt.Errorf("no PDU")
	}
	pduTag := data[offset]
	if pduTag != 0xA2 {
		return "", "", fmt.Errorf("expected GetResponse PDU (0xA2), got 0x%02X", pduTag)
	}
	offset++
	if offset >= len(data) {
		return "", "", fmt.Errorf("PDU length field missing")
	}
	pduLen, lenBytes := decodeBERLength(data[offset:])
	offset += lenBytes

	if offset+pduLen > len(data) {
		// Truncated but we have a GetResponse — still valid.
		pduLen = len(data) - offset
	}

	// Skip request-id, error-status, error-index (3 INTEGERs).
	for i := 0; i < 3; i++ {
		if offset+2 > len(data) {
			break
		}
		if data[offset] != 0x02 {
			break
		}
		fieldLen := int(data[offset+1])
		offset += 2 + fieldLen
	}

	// VarBindList SEQUENCE
	if offset >= len(data) || data[offset] != 0x30 {
		// No VarBind — but GetResponse was valid, return minimal info.
		return "(no sysDescr in response)", version, nil
	}
	offset++
	vblLen, vblLenBytes := decodeBERLength(data[offset:])
	offset += vblLenBytes
	_ = vblLen

	// First VarBind SEQUENCE
	if offset >= len(data) || data[offset] != 0x30 {
		return "(no VarBind)", version, nil
	}
	offset++
	vbLen, vbLenBytes := decodeBERLength(data[offset:])
	offset += vbLenBytes
	_ = vbLen

	// Skip OID
	if offset+2 > len(data) || data[offset] != 0x06 {
		return "(OID missing)", version, nil
	}
	oidLen := int(data[offset+1])
	offset += 2 + oidLen

	// Value: OCTET STRING (sysDescr)
	if offset+2 > len(data) {
		return "(value missing)", version, nil
	}
	valTag := data[offset]
	valLen, valLenBytes := decodeBERLength(data[offset+1:])
	offset += 1 + valLenBytes

	if valTag == 0x04 || valTag == 0x05 { // OCTET STRING or NULL
		if offset+valLen <= len(data) {
			sysDescr = strings.TrimSpace(string(data[offset : offset+valLen]))
		}
	} else {
		// May be another type — hex dump it.
		end := offset + valLen
		if end > len(data) {
			end = len(data)
		}
		sysDescr = fmt.Sprintf("(type=0x%02X) %s", valTag, hex.EncodeToString(data[offset:end]))
	}

	if sysDescr == "" {
		sysDescr = "(empty sysDescr)"
	}
	return sysDescr, version, nil
}

// decodeBERLength decodes a BER-encoded length field and returns (length, bytesConsumed).
func decodeBERLength(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 1
	}
	if data[0]&0x80 == 0 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7F)
	if numBytes == 0 || numBytes > 4 || 1+numBytes > len(data) {
		return 0, 1
	}
	length := 0
	for i := 1; i <= numBytes; i++ {
		length = (length << 8) | int(data[i])
	}
	return length, 1 + numBytes
}

// ─────────────────────────────────────────────────────────────
//  BER encoding helpers
// ─────────────────────────────────────────────────────────────

func berLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	if n < 256 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func berSequence(contents []byte) []byte {
	return append(append([]byte{0x30}, berLength(len(contents))...), contents...)
}

func berTagged(tag byte, contents []byte) []byte {
	return append(append([]byte{tag}, berLength(len(contents))...), contents...)
}

func berInt(v int64) []byte {
	// Minimal encoding: find the fewest bytes needed.
	if v == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	var b []byte
	n := v
	for n != 0 && n != -1 {
		b = append([]byte{byte(n & 0xFF)}, b...)
		n >>= 8
	}
	// Ensure no sign extension confusion.
	if v > 0 && len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	if v < 0 && len(b) > 0 && b[0]&0x80 == 0 {
		b = append([]byte{0xFF}, b...)
	}
	if len(b) == 0 {
		b = []byte{0x00}
	}
	return append([]byte{0x02, byte(len(b))}, b...)
}

func berOctetString(s []byte) []byte {
	return append(append([]byte{0x04}, berLength(len(s))...), s...)
}

func berNull() []byte {
	return []byte{0x05, 0x00}
}

func berOID(encoded []byte) []byte {
	return append(append([]byte{0x06}, berLength(len(encoded))...), encoded...)
}

// encodeOID encodes an OID arc slice into the compact BER OID format.
// The first two arcs are merged: first*40 + second.
func encodeOID(arcs []uint32) []byte {
	if len(arcs) < 2 {
		return nil
	}
	var out []byte
	out = append(out, byte(arcs[0]*40+arcs[1]))
	for _, arc := range arcs[2:] {
		out = append(out, encodeBase128(arc)...)
	}
	return out
}

// encodeBase128 encodes an unsigned integer in base-128 (OID sub-identifier format).
func encodeBase128(v uint32) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v&0x7F) | 0x80}, b...)
		v >>= 7
	}
	// Clear the high bit on the last byte.
	b[len(b)-1] &= 0x7F
	return b
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func truncateSNMP(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
