// Package scanner — Active Directory enumeration via LDAP.
//
// Performs non-destructive read-only LDAP queries:
//   - Domain info (naming context, domain SID, functional level)
//   - User enumeration (SAM account names, UPN, last logon, password flags)
//   - Group enumeration (members of privileged groups: Domain Admins, etc.)
//   - Password policy (min length, lockout threshold, complexity)
//   - Computer accounts (hostnames, OS versions)
//   - Identifies kerberoastable accounts (servicePrincipalName set)
//   - Identifies AS-REP roastable accounts (DONT_REQUIRE_PREAUTH flag)
//   - Detects unconstrained delegation
//
// Requires only LDAP read access (anonymous or authenticated).

package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/xarex/probe/grpc/pb"
)

const (
	ldapPort    = 389
	ldapsPort   = 636
	ldapTimeout = 10 * time.Second

	// UAC flags
	uacDontRequirePreauth   = 0x00400000
	uacUnconstrainedDelegation = 0x00080000
	uacDisabled             = 0x00000002
	uacPasswordNeverExpires  = 0x00010000
)

// ADEnumerator performs LDAP-based Active Directory enumeration.
type ADEnumerator struct {
	logger *slog.Logger
}

// NewADEnumerator returns a ready-to-use ADEnumerator.
func NewADEnumerator(logger *slog.Logger) *ADEnumerator {
	return &ADEnumerator{logger: logger}
}

// ADEnumResult holds everything discovered about the AD environment.
type ADEnumResult struct {
	Domain              string
	NamingContext       string
	DomainSID           string
	FunctionalLevel     string
	TotalUsers          int
	KerberoastableUsers []string
	ASREPRoastableUsers []string
	UnconstrainedDelegation []string
	PrivilegedUsers     []string // members of DA, EA, Schema Admins
	PasswordPolicy      *PasswordPolicy
	ComputerCount       int
	ServiceAccounts     int
	Findings            []*pb.Finding
}

type PasswordPolicy struct {
	MinLength          int
	MaxAge             string
	LockoutThreshold   int
	Complexity         bool
	HistoryCount       int
}

// Enumerate performs LDAP queries against host:389 or host:636.
// Returns a list of security findings.
func (e *ADEnumerator) Enumerate(ctx context.Context, host string) ([]*pb.Finding, error) {
	e.logger.Info("starting AD enumeration", "host", host)

	conn, baseDN, err := e.connect(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("ldap connect to %s: %w", host, err)
	}
	defer conn.Close()

	result := &ADEnumResult{}

	// 1. Get domain info
	if err := e.queryDomainInfo(conn, baseDN, result); err != nil {
		e.logger.Warn("domain info query failed", "error", err)
	}

	// 2. Password policy
	if err := e.queryPasswordPolicy(conn, baseDN, result); err != nil {
		e.logger.Warn("password policy query failed", "error", err)
	}

	// 3. User enumeration
	if err := e.queryUsers(conn, baseDN, result); err != nil {
		e.logger.Warn("user enumeration failed", "error", err)
	}

	// 4. Computer accounts
	if err := e.queryComputers(conn, baseDN, result); err != nil {
		e.logger.Warn("computer enumeration failed", "error", err)
	}

	// 5. Privileged group members
	if err := e.queryPrivilegedGroups(conn, baseDN, result); err != nil {
		e.logger.Warn("privileged group query failed", "error", err)
	}

	return e.buildFindings(host, result), nil
}

// ─────────────────────────────────────────────
//  LDAP connection
// ─────────────────────────────────────────────

func (e *ADEnumerator) connect(ctx context.Context, host string) (*ldap.Conn, string, error) {
	// Try anonymous bind on LDAP (389) first, fall back to LDAPS (636)
	addr := net.JoinHostPort(host, strconv.Itoa(ldapPort))

	dialCtx, cancel := context.WithTimeout(ctx, ldapTimeout)
	defer cancel()

	conn, err := ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(&net.Dialer{
		Timeout: ldapTimeout,
	}))
	if err != nil {
		// Try LDAPS
		tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		addrTLS := net.JoinHostPort(host, strconv.Itoa(ldapsPort))
		conn, err = ldap.DialURL("ldaps://"+addrTLS, ldap.DialWithTLSConfig(tlsConf))
		if err != nil {
			return nil, "", fmt.Errorf("ldap/ldaps connect: %w", err)
		}
	}

	_ = dialCtx

	// Anonymous bind (read-only — many AD deployments allow this)
	if err := conn.UnauthenticatedBind(""); err != nil {
		// Try empty credentials
		_ = conn.Bind("", "")
	}

	// Discover base DN from RootDSE
	baseDN, err := e.getRootDSE(conn)
	if err != nil {
		return nil, "", fmt.Errorf("rootDSE: %w", err)
	}

	return conn, baseDN, nil
}

func (e *ADEnumerator) getRootDSE(conn *ldap.Conn) (string, error) {
	req := ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 5, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "rootDomainNamingContext"},
		nil,
	)
	result, err := conn.Search(req)
	if err != nil {
		return "", err
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("empty RootDSE response")
	}
	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		baseDN = result.Entries[0].GetAttributeValue("rootDomainNamingContext")
	}
	return baseDN, nil
}

// ─────────────────────────────────────────────
//  Query methods
// ─────────────────────────────────────────────

func (e *ADEnumerator) queryDomainInfo(conn *ldap.Conn, baseDN string, result *ADEnumResult) error {
	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 5, false,
		"(objectClass=domain)",
		[]string{"dc", "objectSid", "msDS-Behavior-Version"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return err
	}
	if len(res.Entries) > 0 {
		result.NamingContext = baseDN
		// Convert DN to domain name
		parts := strings.Split(baseDN, ",")
		var domainParts []string
		for _, p := range parts {
			if strings.HasPrefix(strings.ToUpper(p), "DC=") {
				domainParts = append(domainParts, p[3:])
			}
		}
		result.Domain = strings.Join(domainParts, ".")

		level := res.Entries[0].GetAttributeValue("msDS-Behavior-Version")
		result.FunctionalLevel = adFunctionalLevel(level)
	}
	return nil
}

func (e *ADEnumerator) queryPasswordPolicy(conn *ldap.Conn, baseDN string, result *ADEnumResult) error {
	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 5, false,
		"(objectClass=domain)",
		[]string{"minPwdLength", "pwdHistoryLength", "lockoutThreshold", "pwdProperties", "maxPwdAge"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return err
	}
	if len(res.Entries) == 0 {
		return nil
	}
	entry := res.Entries[0]
	minLen, _ := strconv.Atoi(entry.GetAttributeValue("minPwdLength"))
	histLen, _ := strconv.Atoi(entry.GetAttributeValue("pwdHistoryLength"))
	lockout, _ := strconv.Atoi(entry.GetAttributeValue("lockoutThreshold"))
	props, _ := strconv.Atoi(entry.GetAttributeValue("pwdProperties"))
	complexity := (props & 1) != 0

	// maxPwdAge is in 100ns intervals; convert to days
	maxAgeRaw, _ := strconv.ParseInt(entry.GetAttributeValue("maxPwdAge"), 10, 64)
	maxAgeDays := -maxAgeRaw / (864000000000)
	maxAgeStr := fmt.Sprintf("%d days", maxAgeDays)
	if maxAgeDays <= 0 {
		maxAgeStr = "never expires"
	}

	result.PasswordPolicy = &PasswordPolicy{
		MinLength:        minLen,
		MaxAge:           maxAgeStr,
		LockoutThreshold: lockout,
		Complexity:       complexity,
		HistoryCount:     histLen,
	}
	return nil
}

func (e *ADEnumerator) queryUsers(conn *ldap.Conn, baseDN string, result *ADEnumResult) error {
	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1000, 15, false,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName", "userPrincipalName", "userAccountControl", "servicePrincipalName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return err
	}

	result.TotalUsers = len(res.Entries)
	for _, entry := range res.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		uac, _ := strconv.ParseInt(entry.GetAttributeValue("userAccountControl"), 10, 64)
		spns := entry.GetAttributeValues("servicePrincipalName")

		// Kerberoastable: has SPN and is not disabled
		if len(spns) > 0 && (uac&int64(uacDisabled)) == 0 {
			result.KerberoastableUsers = append(result.KerberoastableUsers, sam)
			result.ServiceAccounts++
		}

		// AS-REP roastable: DONT_REQUIRE_PREAUTH set
		if (uac & int64(uacDontRequirePreauth)) != 0 {
			result.ASREPRoastableUsers = append(result.ASREPRoastableUsers, sam)
		}

		// Unconstrained delegation (excluding DC accounts)
		if (uac & int64(uacUnconstrainedDelegation)) != 0 {
			result.UnconstrainedDelegation = append(result.UnconstrainedDelegation, sam)
		}
	}
	return nil
}

func (e *ADEnumerator) queryComputers(conn *ldap.Conn, baseDN string, result *ADEnumResult) error {
	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 500, 10, false,
		"(objectClass=computer)",
		[]string{"sAMAccountName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return err
	}
	result.ComputerCount = len(res.Entries)
	return nil
}

func (e *ADEnumerator) queryPrivilegedGroups(conn *ldap.Conn, baseDN string, result *ADEnumResult) error {
	privilegedGroups := []string{
		"Domain Admins",
		"Enterprise Admins",
		"Schema Admins",
		"Administrators",
		"Account Operators",
		"Backup Operators",
	}

	for _, groupName := range privilegedGroups {
		filter := fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupName))
		req := ldap.NewSearchRequest(
			baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 5, false,
			filter, []string{"member"}, nil,
		)
		res, err := conn.Search(req)
		if err != nil || len(res.Entries) == 0 {
			continue
		}
		members := res.Entries[0].GetAttributeValues("member")
		for _, m := range members {
			// Extract CN from DN
			cn := extractCN(m)
			label := fmt.Sprintf("%s (member of %s)", cn, groupName)
			result.PrivilegedUsers = append(result.PrivilegedUsers, label)
		}
	}
	return nil
}

// ─────────────────────────────────────────────
//  Finding builder
// ─────────────────────────────────────────────

func (e *ADEnumerator) buildFindings(host string, result *ADEnumResult) []*pb.Finding {
	var findings []*pb.Finding
	now := time.Now().UnixMilli()

	// 1. Domain info finding (info)
	if result.Domain != "" {
		findings = append(findings, &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        host,
			Port:        int32(ldapPort),
			Protocol:    "tcp",
			Service:     "ldap",
			Severity:    pb.Severity_INFO,
			Title:       fmt.Sprintf("Active Directory Domain: %s", result.Domain),
			Description: fmt.Sprintf("Domain: %s | Functional Level: %s | Users: %d | Computers: %d | Service Accounts: %d", result.Domain, result.FunctionalLevel, result.TotalUsers, result.ComputerCount, result.ServiceAccounts),
			Evidence:    fmt.Sprintf("BaseDN: %s", result.NamingContext),
			Remediation: "Ensure AD is properly configured and hardened per Microsoft Security Baselines.",
			Metadata:    map[string]string{"domain": result.Domain, "functional_level": result.FunctionalLevel},
			Timestamp:   now,
		})
	}

	// 2. Kerberoastable accounts (HIGH)
	if len(result.KerberoastableUsers) > 0 {
		findings = append(findings, &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        host,
			Port:        int32(88),
			Protocol:    "tcp",
			Service:     "kerberos",
			Severity:    pb.Severity_HIGH,
			Title:       fmt.Sprintf("Kerberoastable Accounts Found (%d)", len(result.KerberoastableUsers)),
			Description: "Service accounts with SPNs set can be targeted by Kerberoasting — an offline attack that extracts and cracks service ticket hashes without authentication.",
			Evidence:    fmt.Sprintf("Accounts: %s", strings.Join(result.KerberoastableUsers, ", ")),
			Remediation: "1. Use Group Managed Service Accounts (gMSA) with auto-rotating 120+ char passwords.\n2. Audit SPNs regularly: Get-ADUser -Filter {ServicePrincipalName -like '*'}\n3. Enable AES-only Kerberos encryption for service accounts.",
			CveId:       "",
			Metadata: map[string]string{
				"attack_technique_ids": "T1558.003",
				"accounts":             strings.Join(result.KerberoastableUsers, ","),
				"count":                strconv.Itoa(len(result.KerberoastableUsers)),
			},
			Timestamp: now,
		})
	}

	// 3. AS-REP Roastable accounts (HIGH)
	if len(result.ASREPRoastableUsers) > 0 {
		findings = append(findings, &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        host,
			Port:        int32(88),
			Protocol:    "tcp",
			Service:     "kerberos",
			Severity:    pb.Severity_HIGH,
			Title:       fmt.Sprintf("AS-REP Roastable Accounts Found (%d)", len(result.ASREPRoastableUsers)),
			Description: "Accounts with 'Do not require Kerberos pre-authentication' enabled allow unauthenticated AS-REP roasting — extracting and cracking account hashes without any credentials.",
			Evidence:    fmt.Sprintf("Accounts: %s", strings.Join(result.ASREPRoastableUsers, ", ")),
			Remediation: "1. Enable Kerberos pre-authentication for all accounts.\n2. Audit: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}\n3. Use long, complex passwords if pre-auth cannot be enabled.",
			Metadata: map[string]string{
				"attack_technique_ids": "T1558.004",
				"accounts":             strings.Join(result.ASREPRoastableUsers, ","),
			},
			Timestamp: now,
		})
	}

	// 4. Unconstrained delegation (CRITICAL)
	if len(result.UnconstrainedDelegation) > 0 {
		findings = append(findings, &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        host,
			Port:        int32(ldapPort),
			Protocol:    "tcp",
			Service:     "ldap",
			Severity:    pb.Severity_CRITICAL,
			Title:       fmt.Sprintf("Unconstrained Kerberos Delegation (%d accounts)", len(result.UnconstrainedDelegation)),
			Description: "Accounts with unconstrained delegation store TGTs for any user who authenticates to them. An attacker who compromises such an account can impersonate ANY user including domain admins (Pass-the-Ticket, Golden Ticket).",
			Evidence:    fmt.Sprintf("Accounts: %s", strings.Join(result.UnconstrainedDelegation, ", ")),
			Remediation: "1. Replace unconstrained with constrained or resource-based constrained delegation.\n2. Audit: Get-ADComputer -Filter {TrustedForDelegation -eq $true}\n3. Protect these accounts with Protected Users security group.",
			Metadata: map[string]string{
				"attack_technique_ids": "T1558,T1134",
				"accounts":             strings.Join(result.UnconstrainedDelegation, ","),
			},
			Timestamp: now,
		})
	}

	// 5. Weak password policy (MEDIUM / HIGH)
	if result.PasswordPolicy != nil {
		pp := result.PasswordPolicy
		var issues []string
		severity := pb.Severity_INFO

		if pp.MinLength < 12 {
			issues = append(issues, fmt.Sprintf("Min password length is only %d (recommend ≥14)", pp.MinLength))
			severity = pb.Severity_MEDIUM
		}
		if pp.LockoutThreshold == 0 {
			issues = append(issues, "No account lockout threshold — brute force attacks are possible")
			severity = pb.Severity_HIGH
		} else if pp.LockoutThreshold > 10 {
			issues = append(issues, fmt.Sprintf("Lockout threshold is %d (recommend ≤5)", pp.LockoutThreshold))
		}
		if !pp.Complexity {
			issues = append(issues, "Password complexity NOT enforced")
			if severity < pb.Severity_MEDIUM {
				severity = pb.Severity_MEDIUM
			}
		}
		if pp.MaxAge == "never expires" {
			issues = append(issues, "Passwords never expire")
		}

		if len(issues) > 0 {
			findings = append(findings, &pb.Finding{
				FindingId:   uuid.NewString(),
				Host:        host,
				Port:        int32(ldapPort),
				Protocol:    "tcp",
				Service:     "ldap",
				Severity:    severity,
				Title:       "Weak Active Directory Password Policy",
				Description: "The domain password policy has weaknesses that increase the risk of credential attacks.",
				Evidence:    strings.Join(issues, "\n"),
				Remediation: "Enforce: min 14 chars, complexity on, lockout ≤5 attempts, lockout duration ≥30 min, history ≥24 passwords. Consider Microsoft LAPS and Windows FGPP.",
				Metadata: map[string]string{
					"min_length":        strconv.Itoa(pp.MinLength),
					"lockout_threshold": strconv.Itoa(pp.LockoutThreshold),
					"complexity":        strconv.FormatBool(pp.Complexity),
					"max_age":           pp.MaxAge,
				},
				Timestamp: now,
			})
		}
	}

	// 6. Privileged users discovered (info)
	if len(result.PrivilegedUsers) > 0 {
		findings = append(findings, &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        host,
			Port:        int32(ldapPort),
			Protocol:    "tcp",
			Service:     "ldap",
			Severity:    pb.Severity_INFO,
			Title:       fmt.Sprintf("Privileged Group Members Enumerated (%d)", len(result.PrivilegedUsers)),
			Description: "The following accounts are members of highly privileged AD groups. These are prime targets for attackers.",
			Evidence:    strings.Join(result.PrivilegedUsers, "\n"),
			Remediation: "1. Apply tiered admin model (Tier 0/1/2).\n2. Enable Privileged Identity Management (PIM).\n3. Use Protected Users group for all DA/EA accounts.\n4. Implement Privileged Access Workstations (PAW).",
			Metadata:    map[string]string{"attack_technique_ids": "T1078.002", "count": strconv.Itoa(len(result.PrivilegedUsers))},
			Timestamp:   now,
		})
	}

	e.logger.Info("AD enumeration complete",
		"host", host,
		"domain", result.Domain,
		"users", result.TotalUsers,
		"kerberoastable", len(result.KerberoastableUsers),
		"asrep_roastable", len(result.ASREPRoastableUsers),
		"findings", len(findings),
	)

	return findings
}

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────

func extractCN(dn string) string {
	parts := strings.Split(dn, ",")
	if len(parts) > 0 && strings.HasPrefix(strings.ToUpper(parts[0]), "CN=") {
		return parts[0][3:]
	}
	return dn
}

func adFunctionalLevel(level string) string {
	levels := map[string]string{
		"0": "Windows 2000",
		"1": "Windows Server 2003 Interim",
		"2": "Windows Server 2003",
		"3": "Windows Server 2008",
		"4": "Windows Server 2008 R2",
		"5": "Windows Server 2012",
		"6": "Windows Server 2012 R2",
		"7": "Windows Server 2016/2019/2022",
	}
	if name, ok := levels[level]; ok {
		return name
	}
	return fmt.Sprintf("Level %s", level)
}
