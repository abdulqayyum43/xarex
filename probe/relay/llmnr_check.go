package relay

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xarex/probe/grpc/pb"
)

const (
	llmnrMulticast = "224.0.0.252"
	llmnrPort      = 5355
	nbtnsPort      = 137

	llmnrReadTimeout = 3 * time.Second
	nbtnsTimeout     = 3 * time.Second
)

// LLMNRChecker detects whether LLMNR (Link-Local Multicast Name Resolution)
// and/or NBT-NS (NetBIOS Name Service) are active on the network.
//
// Both protocols are abused by Responder-style tools: they respond to queries
// for non-existent hostnames, enabling credential capture via NTLM coercion.
//
// This check is entirely non-destructive:
//   - It sends a single LLMNR query for a randomly generated, non-existent hostname
//     to the multicast address 224.0.0.252:5355.
//   - It sends a single NBT-NS query for a random hostname as a UDP broadcast to
//     the subnet's broadcast address on port 137.
//   - Any response indicates the protocol is active on the network.
type LLMNRChecker struct {
	logger *slog.Logger
}

// NewLLMNRChecker returns a ready-to-use LLMNRChecker.
func NewLLMNRChecker(logger *slog.Logger) *LLMNRChecker {
	return &LLMNRChecker{logger: logger}
}

// Check probes for LLMNR and NBT-NS activity on the subnet.
// subnet is a CIDR string (e.g. "192.168.1.0/24"); it is used only to derive the
// broadcast address for the NBT-NS check.
func (c *LLMNRChecker) Check(ctx context.Context, subnet string) (*pb.Finding, error) {
	// Generate a random hostname that should never exist on any network.
	fakeName := randomHostname()
	c.logger.Info("checking LLMNR/NBT-NS", "subnet", subnet, "probe_name", fakeName)

	llmnrResp, llmnrErr := c.checkLLMNR(ctx, fakeName)
	nbtnsResp, nbtnsErr := c.checkNBTNS(ctx, subnet, fakeName)

	// Log errors but treat them as non-fatal (protocol may just be blocked).
	if llmnrErr != nil {
		c.logger.Debug("LLMNR probe error (may indicate protocol is absent)", "error", llmnrErr)
	}
	if nbtnsErr != nil {
		c.logger.Debug("NBT-NS probe error (may indicate protocol is absent)", "error", nbtnsErr)
	}

	llmnrActive := llmnrResp != nil
	nbtnsActive := nbtnsResp != nil

	c.logger.Info("LLMNR/NBT-NS check result",
		"subnet", subnet,
		"llmnr_active", llmnrActive,
		"nbtns_active", nbtnsActive,
	)

	finding := buildLLMNRFinding(subnet, fakeName, llmnrActive, nbtnsActive, llmnrResp, nbtnsResp)
	return finding, nil
}

// ─────────────────────────────────────────────
//  LLMNR probe
// ─────────────────────────────────────────────

// checkLLMNR sends an LLMNR query to the multicast address and waits for any reply.
// Returns the responder's address if a response is received, nil otherwise.
func (c *LLMNRChecker) checkLLMNR(ctx context.Context, name string) (net.Addr, error) {
	// Bind to a random ephemeral UDP port.
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("llmnr listen: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(llmnrReadTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	query := buildLLMNRQuery(name)
	dst := &net.UDPAddr{IP: net.ParseIP(llmnrMulticast), Port: llmnrPort}
	if _, err := conn.WriteTo(query, dst); err != nil {
		return nil, fmt.Errorf("llmnr write: %w", err)
	}

	buf := make([]byte, 512)
	_, addr, err := conn.ReadFrom(buf)
	if err != nil {
		// Timeout or no reply — not an error condition for this check.
		return nil, nil //nolint:nilerr
	}
	return addr, nil
}

// buildLLMNRQuery constructs a minimal LLMNR/DNS-SD query for the given hostname.
// Format is identical to DNS (RFC 4795 §2.1.1).
func buildLLMNRQuery(name string) []byte {
	// Transaction ID: random.
	txID := uint16(rand.Intn(0xFFFF)) //nolint:gosec
	buf := make([]byte, 0, 64)

	appendUint16 := func(v uint16) {
		buf = append(buf, byte(v>>8), byte(v))
	}

	appendUint16(txID) // Transaction ID
	appendUint16(0)    // Flags: standard query
	appendUint16(1)    // Questions: 1
	appendUint16(0)    // Answers: 0
	appendUint16(0)    // Authority: 0
	appendUint16(0)    // Additional: 0

	// Encode QNAME.
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // root label

	appendUint16(0x0001) // QTYPE  = A
	appendUint16(0x0001) // QCLASS = IN

	return buf
}

// ─────────────────────────────────────────────
//  NBT-NS probe
// ─────────────────────────────────────────────

// checkNBTNS sends a NetBIOS Name Service query as a UDP broadcast on port 137.
func (c *LLMNRChecker) checkNBTNS(ctx context.Context, subnet, name string) (net.Addr, error) {
	broadcast, err := subnetBroadcast(subnet)
	if err != nil {
		return nil, fmt.Errorf("derive broadcast: %w", err)
	}

	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("nbtns listen: %w", err)
	}
	defer conn.Close()

	// Enable broadcast on the socket (Linux default allows this; on some platforms
	// we may need SO_BROADCAST via syscall — best-effort here).
	deadline := time.Now().Add(nbtnsTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	query := buildNBTNSQuery(name)
	dst := &net.UDPAddr{IP: net.ParseIP(broadcast), Port: nbtnsPort}
	if _, err := conn.WriteTo(query, dst); err != nil {
		return nil, fmt.Errorf("nbtns write: %w", err)
	}

	buf := make([]byte, 512)
	_, addr, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, nil //nolint:nilerr
	}
	return addr, nil
}

// buildNBTNSQuery constructs a minimal NBT-NS Name Query Request (RFC 1002 §4.2.12).
func buildNBTNSQuery(name string) []byte {
	txID := uint16(rand.Intn(0xFFFF)) //nolint:gosec

	buf := make([]byte, 0, 50)
	appendUint16 := func(v uint16) { buf = append(buf, byte(v>>8), byte(v)) }

	appendUint16(txID)   // NAME_TRN_ID
	appendUint16(0x0110) // FLAGS: opcode=0 (query), NM flag, recursion desired
	appendUint16(1)      // QDCOUNT
	appendUint16(0)      // ANCOUNT
	appendUint16(0)      // NSCOUNT
	appendUint16(0)      // ARCOUNT

	// QUESTION_NAME: NetBIOS first-level encoded (32-byte + length + null).
	encoded := nbtFirstLevelEncode(name)
	buf = append(buf, byte(len(encoded)))
	buf = append(buf, encoded...)
	buf = append(buf, 0x00) // root label

	appendUint16(0x0020) // QTYPE  = NB (NetBIOS general name)
	appendUint16(0x0001) // QCLASS = IN

	return buf
}

// nbtFirstLevelEncode applies NetBIOS first-level name encoding:
// Each character of the 16-byte padded name is split into two nibbles and
// each nibble has 'A' added (RFC 1001 §14.1).
func nbtFirstLevelEncode(name string) []byte {
	// Pad or truncate to 15 chars + null suffix byte (0x20 = file server service).
	padded := make([]byte, 16)
	copy(padded, []byte(strings.ToUpper(name)))
	for i := len(name); i < 15; i++ {
		padded[i] = 0x20
	}
	padded[15] = 0x00 // workstation service

	encoded := make([]byte, 32)
	for i, b := range padded {
		encoded[i*2] = 'A' + b>>4
		encoded[i*2+1] = 'A' + b&0x0F
	}
	return encoded
}

// ─────────────────────────────────────────────
//  Finding builder
// ─────────────────────────────────────────────

func buildLLMNRFinding(
	subnet, probeName string,
	llmnrActive, nbtnsActive bool,
	llmnrResponder, nbtnsResponder net.Addr,
) *pb.Finding {
	f := &pb.Finding{
		FindingId: uuid.NewString(),
		Protocol:  "udp",
		Timestamp: time.Now().UnixMilli(),
		Metadata: map[string]string{
			"subnet":       subnet,
			"probe_name":   probeName,
			"llmnr_active": strconv.FormatBool(llmnrActive),
			"nbtns_active": strconv.FormatBool(nbtnsActive),
		},
	}

	if llmnrResponder != nil {
		f.Metadata["llmnr_responder"] = llmnrResponder.String()
	}
	if nbtnsResponder != nil {
		f.Metadata["nbtns_responder"] = nbtnsResponder.String()
	}

	if !llmnrActive && !nbtnsActive {
		f.Severity = pb.Severity_INFO
		f.Title = "LLMNR and NBT-NS Not Detected"
		f.Description = fmt.Sprintf(
			"No response received to LLMNR or NBT-NS queries for %q on subnet %s. "+
				"Neither protocol appears to be active.",
			probeName, subnet,
		)
		f.Evidence = "No hosts responded to LLMNR multicast or NBT-NS broadcast queries."
		return f
	}

	var active []string
	var evidence []string
	if llmnrActive {
		active = append(active, "LLMNR")
		evidence = append(evidence, fmt.Sprintf(
			"LLMNR response received from %s to query for %q (224.0.0.252:5355)",
			llmnrResponder, probeName,
		))
		f.Port = llmnrPort
	}
	if nbtnsActive {
		active = append(active, "NBT-NS")
		evidence = append(evidence, fmt.Sprintf(
			"NBT-NS response received from %s to broadcast query for %q (port 137)",
			nbtnsResponder, probeName,
		))
		if f.Port == 0 {
			f.Port = nbtnsPort
		}
	}

	f.Severity = pb.Severity_MEDIUM
	f.Title = fmt.Sprintf("%s Poisoning Attack Surface Detected", strings.Join(active, " and "))
	f.Description = fmt.Sprintf(
		"%s %s active on subnet %s. An attacker on the same network can run "+
			"Responder or Inveigh to intercept broadcast/multicast name resolution "+
			"requests and capture or relay NTLM credentials without any prior foothold.",
		strings.Join(active, " and "),
		verbPhrase(len(active)),
		subnet,
	)
	f.Evidence = strings.Join(evidence, "\n")
	f.Remediation = "Disable LLMNR via Group Policy: Computer Configuration → " +
		"Administrative Templates → Network → DNS Client → " +
		"\"Turn off multicast name resolution\" = Enabled.\n" +
		"Disable NBT-NS per-adapter via Network Adapter Properties → TCP/IP → Advanced → WINS → " +
		"\"Disable NetBIOS over TCP/IP\"."

	return f
}

func verbPhrase(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// ─────────────────────────────────────────────
//  Utility
// ─────────────────────────────────────────────

// randomHostname generates a random label that is almost certainly not resolvable.
func randomHostname() string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	const length = 12
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))] //nolint:gosec
	}
	return "xarex-" + string(b)
}

// subnetBroadcast returns the broadcast IP string for a CIDR subnet.
func subnetBroadcast(cidr string) (string, error) {
	if cidr == "" {
		return "255.255.255.255", nil
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	ip := network.IP.To4()
	if ip == nil {
		return "", fmt.Errorf("only IPv4 supported")
	}
	mask := network.Mask
	broadcast := make(net.IP, 4)
	for i := range ip {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast.String(), nil
}

