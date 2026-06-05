// Package scanner — DNS Zone Transfer Module (task type 12)
//
// Attempts an AXFR (Authoritative Zone Transfer) request against a DNS server.
// A successful zone transfer reveals the entire DNS namespace of a domain —
// hostnames, IP mappings, mail servers, internal service names — providing an
// attacker with a detailed reconnaissance map before any exploitation.
//
// RFC 5936 defines the AXFR protocol. We speak raw DNS over TCP port 53,
// building the query by hand using encoding/binary so we have zero external
// dependencies beyond the standard library.
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

// DNSZoneTransferScanner attempts AXFR zone transfers against target DNS servers.
type DNSZoneTransferScanner struct {
	logger  *slog.Logger
	timeout time.Duration
}

// NewDNSZoneTransferScanner returns a ready DNSZoneTransferScanner.
func NewDNSZoneTransferScanner(logger *slog.Logger) *DNSZoneTransferScanner {
	return &DNSZoneTransferScanner{
		logger:  logger,
		timeout: 10 * time.Second,
	}
}

// Scan attempts AXFR for every domain hinted at by host. It probes:
//  1. The host itself as a zone name (e.g., "example.com").
//  2. The parent domain of the host (e.g., if host is "ns1.example.com" → "example.com").
func (s *DNSZoneTransferScanner) Scan(ctx context.Context, host string) ([]*pb.Finding, error) {
	// Build candidate zone names from the host.
	zones := s.deriveZones(host)

	var findings []*pb.Finding
	for _, zone := range zones {
		records, err := s.attemptAXFR(ctx, host, zone)
		if err != nil {
			s.logger.Debug("axfr attempt failed",
				"server", host, "zone", zone, "error", err)
			continue
		}
		if len(records) == 0 {
			continue
		}

		// Confirmed zone transfer if we got records back.
		sev := pb.Severity_INFO
		if len(records) > 5 {
			sev = pb.Severity_HIGH
		} else if len(records) > 0 {
			sev = pb.Severity_MEDIUM
		}

		// Build compact evidence from the first 50 records.
		evRecords := records
		truncated := false
		if len(evRecords) > 50 {
			evRecords = records[:50]
			truncated = true
		}
		var evBuilder strings.Builder
		fmt.Fprintf(&evBuilder, "AXFR zone transfer for '%s' from %s succeeded.\n", zone, host)
		fmt.Fprintf(&evBuilder, "Records returned: %d\n\n", len(records))
		for _, r := range evRecords {
			evBuilder.WriteString(r)
			evBuilder.WriteByte('\n')
		}
		if truncated {
			fmt.Fprintf(&evBuilder, "... (%d records truncated)\n", len(records)-50)
		}

		findings = append(findings, &pb.Finding{
			FindingId: uuid.NewString(),
			Host:      host,
			Port:      53,
			Protocol:  "tcp",
			Service:   "dns",
			Severity:  sev,
			Title:     fmt.Sprintf("DNS Zone Transfer Allowed: %s", zone),
			Description: fmt.Sprintf(
				"The DNS server at %s allows unauthenticated AXFR zone transfer for zone '%s'. "+
					"%d DNS records were retrieved, exposing the entire DNS namespace including "+
					"internal hostnames, IP addresses, mail servers, and service endpoints. "+
					"This information significantly aids attacker reconnaissance.",
				host, zone, len(records)),
			Evidence:    evBuilder.String(),
			Remediation: "Restrict zone transfers to authorised secondary DNS servers only. " +
				"In BIND: 'allow-transfer { <secondary-ip>; };'. " +
				"In Windows DNS: Disable zone transfers or restrict to specific servers. " +
				"Implement TSIG authentication for all zone transfer requests.",
			Metadata: map[string]string{
				"zone":         zone,
				"record_count": fmt.Sprintf("%d", len(records)),
				"server":       host,
				"port":         "53",
			},
			Timestamp: time.Now().UnixMilli(),
		})

		s.logger.Warn("AXFR zone transfer succeeded",
			"server", host, "zone", zone, "records", len(records))
	}

	return findings, nil
}

// deriveZones builds a list of DNS zone names to try from a host/IP string.
func (s *DNSZoneTransferScanner) deriveZones(host string) []string {
	seen := make(map[string]bool)
	var zones []string

	add := func(z string) {
		z = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".")
		if z != "" && !seen[z] {
			seen[z] = true
			zones = append(zones, z)
		}
	}

	// If it's a plain IP, try reverse-lookup to get domain hints.
	if ip := net.ParseIP(host); ip != nil {
		names, err := net.LookupAddr(host)
		if err == nil {
			for _, n := range names {
				n = strings.TrimSuffix(n, ".")
				add(n)
				// Also add parent domain.
				if parts := strings.SplitN(n, ".", 2); len(parts) == 2 {
					add(parts[1])
				}
			}
		}
		return zones
	}

	// Host is a name — add it and its parent domain.
	add(host)
	if parts := strings.SplitN(host, ".", 2); len(parts) == 2 {
		add(parts[1])
	}
	return zones
}

// attemptAXFR sends a raw AXFR query over TCP to server:53 for zone.
// It returns a slice of text-formatted DNS records on success.
func (s *DNSZoneTransferScanner) attemptAXFR(ctx context.Context, server, zone string) ([]string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	d := &net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, fmt.Errorf("dial %s:53: %w", server, err)
	}
	defer conn.Close() //nolint:errcheck

	deadline := time.Now().Add(s.timeout)
	conn.SetDeadline(deadline) //nolint:errcheck

	// Build AXFR query for the zone.
	msgID := uint16(0xABCD)
	query := buildAXFRQuery(msgID, zone)

	// DNS over TCP requires a 2-byte length prefix.
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(query)))
	if _, err = conn.Write(append(lenBuf, query...)); err != nil {
		return nil, fmt.Errorf("write axfr query: %w", err)
	}

	// Collect all response messages (AXFR can span multiple TCP messages).
	var records []string
	sawSOA := false
	sоаCount := 0

	for {
		// Read 2-byte message length.
		var msgLen uint16
		if err = binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
			break
		}
		if msgLen == 0 || msgLen > 65535 {
			break
		}

		msgBuf := make([]byte, msgLen)
		if err = readFull(conn, msgBuf); err != nil {
			break
		}

		parsed, isSoa, rcode, parseErr := parseAXFRResponse(msgBuf)
		if parseErr != nil {
			s.logger.Debug("axfr parse error", "zone", zone, "error", parseErr)
			break
		}

		// RCODE != 0 means server refused or error.
		if rcode != 0 {
			return nil, fmt.Errorf("axfr refused (rcode=%d)", rcode)
		}

		records = append(records, parsed...)

		if isSoa {
			sоаCount++
			if !sawSOA {
				sawSOA = true
			} else {
				// Second SOA marks end of zone transfer.
				break
			}
		}

		// Safety limit.
		if len(records) > 10000 {
			break
		}
	}

	if len(records) == 0 {
		return nil, nil
	}
	return records, nil
}

// buildAXFRQuery constructs a minimal DNS AXFR query message.
//
// Wire format (RFC 1035):
//
//	Header:  ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
//	Question: QNAME(variable) QTYPE(2) QCLASS(2)
func buildAXFRQuery(id uint16, zone string) []byte {
	var msg []byte

	// Header
	msg = append(msg, byte(id>>8), byte(id))   // ID
	msg = append(msg, 0x00, 0x00)               // FLAGS: standard query
	msg = append(msg, 0x00, 0x01)               // QDCOUNT = 1
	msg = append(msg, 0x00, 0x00)               // ANCOUNT = 0
	msg = append(msg, 0x00, 0x00)               // NSCOUNT = 0
	msg = append(msg, 0x00, 0x00)               // ARCOUNT = 0

	// Question: QNAME
	for _, label := range strings.Split(zone, ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00) // root label

	msg = append(msg, 0x00, 0xFC) // QTYPE = AXFR (252)
	msg = append(msg, 0x00, 0x01) // QCLASS = IN

	return msg
}

// parseAXFRResponse parses a DNS response message and returns:
//   - a slice of human-readable record strings
//   - whether the answer section contains a SOA record
//   - the RCODE from the header
//   - any parse error
func parseAXFRResponse(msg []byte) (records []string, isSoa bool, rcode int, err error) {
	if len(msg) < 12 {
		return nil, false, 0, fmt.Errorf("message too short (%d bytes)", len(msg))
	}

	// Parse flags / rcode.
	flags := binary.BigEndian.Uint16(msg[2:4])
	rcode = int(flags & 0x000F)

	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	if anCount == 0 {
		return nil, false, rcode, nil
	}

	// Skip past the header and question section.
	offset := 12
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	for i := 0; i < qdCount; i++ {
		offset, err = skipName(msg, offset)
		if err != nil {
			return nil, false, rcode, err
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Parse answer records.
	for i := 0; i < anCount && offset < len(msg); i++ {
		var name string
		name, offset, err = readName(msg, offset)
		if err != nil {
			break
		}
		if offset+10 > len(msg) {
			break
		}
		rrType := binary.BigEndian.Uint16(msg[offset : offset+2])
		rrClass := binary.BigEndian.Uint16(msg[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(msg[offset+4 : offset+8])
		rdLength := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
		offset += 10

		if offset+rdLength > len(msg) {
			break
		}
		rdata := msg[offset : offset+rdLength]
		offset += rdLength

		typeName := dnsTypeName(rrType)
		rdataStr := formatRdata(rrType, rdata, msg)

		if rrType == 6 { // SOA
			isSoa = true
		}

		_ = rrClass // suppress unused warning
		records = append(records, fmt.Sprintf("%-40s %7d %-8s %s", name, ttl, typeName, rdataStr))
	}

	return records, isSoa, rcode, nil
}

// skipName advances offset past a DNS name (with possible compression pointers).
func skipName(msg []byte, offset int) (int, error) {
	for {
		if offset >= len(msg) {
			return offset, fmt.Errorf("name parsing beyond end of message")
		}
		length := int(msg[offset])
		if length == 0 {
			return offset + 1, nil
		}
		if length&0xC0 == 0xC0 {
			// Compression pointer — 2 bytes.
			return offset + 2, nil
		}
		offset += 1 + length
	}
}

// readName reads a DNS name (handling compression pointers) starting at offset,
// returning the name string and the new offset position.
func readName(msg []byte, offset int) (string, int, error) {
	var labels []string
	visited := make(map[int]bool)
	origOffset := offset
	jumped := false

	for {
		if offset >= len(msg) {
			return "", origOffset, fmt.Errorf("name reading beyond message bounds")
		}
		if visited[offset] {
			return "", origOffset, fmt.Errorf("compression pointer loop detected")
		}
		visited[offset] = true

		length := int(msg[offset])
		if length == 0 {
			if !jumped {
				origOffset = offset + 1
			}
			break
		}
		if length&0xC0 == 0xC0 {
			// Compression pointer.
			if offset+1 >= len(msg) {
				return "", origOffset, fmt.Errorf("compression pointer out of bounds")
			}
			ptr := int(binary.BigEndian.Uint16(msg[offset:offset+2]) & 0x3FFF)
			if !jumped {
				origOffset = offset + 2
			}
			jumped = true
			offset = ptr
			continue
		}
		offset++
		if offset+length > len(msg) {
			return "", origOffset, fmt.Errorf("label out of bounds")
		}
		labels = append(labels, string(msg[offset:offset+length]))
		offset += length
	}

	name := strings.Join(labels, ".")
	if name == "" {
		name = "."
	}
	return name, origOffset, nil
}

// formatRdata returns a human-readable representation of RDATA.
func formatRdata(rrType uint16, rdata []byte, msg []byte) string {
	switch rrType {
	case 1: // A
		if len(rdata) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
		}
	case 28: // AAAA
		if len(rdata) == 16 {
			return net.IP(rdata).String()
		}
	case 2, 5, 12: // NS, CNAME, PTR
		name, _, err := readName(msg, findRdataOffset(msg, rdata))
		if err == nil {
			return name
		}
	case 15: // MX
		if len(rdata) >= 3 {
			pref := binary.BigEndian.Uint16(rdata[0:2])
			name, _, err := readName(msg, findRdataOffset(msg, rdata)+2)
			if err == nil {
				return fmt.Sprintf("%d %s", pref, name)
			}
		}
	case 16: // TXT
		if len(rdata) > 1 {
			txLen := int(rdata[0])
			if txLen+1 <= len(rdata) {
				return fmt.Sprintf("%q", string(rdata[1:1+txLen]))
			}
		}
	case 33: // SRV
		if len(rdata) >= 7 {
			priority := binary.BigEndian.Uint16(rdata[0:2])
			weight := binary.BigEndian.Uint16(rdata[2:4])
			port := binary.BigEndian.Uint16(rdata[4:6])
			name, _, err := readName(msg, findRdataOffset(msg, rdata)+6)
			if err == nil {
				return fmt.Sprintf("%d %d %d %s", priority, weight, port, name)
			}
		}
	}
	// Fallback: hex dump.
	if len(rdata) > 32 {
		rdata = rdata[:32]
	}
	return fmt.Sprintf("0x%X", rdata)
}

// findRdataOffset finds the offset of rdata within msg by pointer comparison.
// This is used as a helper for compression pointer resolution in RDATA.
func findRdataOffset(msg, rdata []byte) int {
	if len(rdata) == 0 {
		return 0
	}
	// Slice header trick — rdata is a sub-slice of msg.
	msgStart := &msg[0]
	rdataStart := &rdata[0]
	// Compute offset by pointer arithmetic via unsafe-free approach.
	for i := range msg {
		if &msg[i] == rdataStart {
			_ = msgStart
			return i
		}
	}
	return 0
}

// dnsTypeName returns the string name of a DNS record type.
func dnsTypeName(t uint16) string {
	names := map[uint16]string{
		1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
		15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR",
		255: "ANY", 252: "AXFR",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE%d", t)
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			if total == len(buf) {
				return nil
			}
			return err
		}
	}
	return nil
}
