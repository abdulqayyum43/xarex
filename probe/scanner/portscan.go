package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/xarex/probe/grpc/pb"
)

const (
	defaultPortTimeout    = 500 * time.Millisecond
	defaultConcurrency    = 100
)

// Top1000Ports is a curated list of the most commonly probed TCP ports.
// Covers IANA well-known + registered ports likely to be found on enterprise networks.
var Top1000Ports = []int{
	// Well-known / standard
	21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 194,
	389, 443, 445, 465, 514, 515, 587, 636, 993, 995,
	// Remote access / management
	1080, 1194, 1433, 1521, 1723, 2049, 2222, 2375, 2376, 3306,
	3389, 3690, 4444, 4848, 5432, 5900, 5984, 6379, 6443, 7001,
	7443, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300,
	9443, 10000, 11211, 15672, 27017, 27018, 27019, 28017,
	// SMB / AD
	88, 389, 464, 593, 3268, 3269, 49152, 49153, 49154, 49155,
	// VoIP / media
	554, 1935, 5060, 5061,
	// ICS / SCADA (detection-only, no exploit)
	102, 502, 4911, 20000, 44818,
	// Databases
	1434, 5984, 6380, 7474, 9042, 50000,
	// Misc services
	161, 162, 177, 500, 520, 623, 1900, 5353,
}

// portServiceMap maps well-known port numbers to service name hints.
var portServiceMap = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	88:    "kerberos",
	102:   "s7comm",
	110:   "pop3",
	111:   "rpcbind",
	119:   "nntp",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	162:   "snmptrap",
	177:   "xdmcp",
	194:   "irc",
	389:   "ldap",
	443:   "https",
	445:   "microsoft-ds",
	464:   "kpasswd",
	465:   "smtps",
	500:   "isakmp",
	502:   "modbus",
	514:   "syslog",
	515:   "lpd",
	520:   "rip",
	554:   "rtsp",
	587:   "submission",
	593:   "http-rpc-epmap",
	623:   "ipmi",
	636:   "ldaps",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1194:  "openvpn",
	1433:  "mssql",
	1434:  "mssql-udp",
	1521:  "oracle",
	1723:  "pptp",
	1900:  "upnp",
	1935:  "rtmp",
	2049:  "nfs",
	2222:  "ssh-alt",
	2375:  "docker",
	2376:  "docker-tls",
	3268:  "ldap-gc",
	3269:  "ldaps-gc",
	3306:  "mysql",
	3389:  "rdp",
	3690:  "svn",
	4444:  "metasploit",
	4848:  "glassfish",
	4911:  "niagara-fox",
	5060:  "sip",
	5061:  "sips",
	5353:  "mdns",
	5432:  "postgresql",
	5900:  "vnc",
	5984:  "couchdb",
	6379:  "redis",
	6380:  "redis-tls",
	6443:  "kubernetes",
	7001:  "weblogic",
	7443:  "weblogic-tls",
	7474:  "neo4j",
	8000:  "http-alt",
	8080:  "http-proxy",
	8081:  "http-alt2",
	8443:  "https-alt",
	8888:  "jupyter",
	9000:  "php-fpm",
	9042:  "cassandra",
	9090:  "prometheus",
	9200:  "elasticsearch",
	9300:  "elasticsearch-transport",
	9443:  "websm",
	10000: "webmin",
	11211: "memcached",
	15672: "rabbitmq-mgmt",
	20000: "dnp3",
	27017: "mongodb",
	27018: "mongodb-shard",
	27019: "mongodb-config",
	28017: "mongodb-web",
	44818: "ethernet-ip",
	50000: "db2",
}

// PortScanner performs TCP connect scans against a target host.
type PortScanner struct {
	logger      *slog.Logger
	timeout     time.Duration
	concurrency int
}

// NewPortScanner returns a PortScanner with sensible defaults.
func NewPortScanner(logger *slog.Logger) *PortScanner {
	return &PortScanner{
		logger:      logger,
		timeout:     defaultPortTimeout,
		concurrency: defaultConcurrency,
	}
}

// WithTimeout overrides the per-port dial timeout.
func (ps *PortScanner) WithTimeout(t time.Duration) *PortScanner {
	ps.timeout = t
	return ps
}

// WithConcurrency overrides the number of parallel goroutines.
func (ps *PortScanner) WithConcurrency(n int) *PortScanner {
	ps.concurrency = n
	return ps
}

// Scan probes the given ports on host and returns those that are open.
// If ports is nil or empty, Top1000Ports is used.
func (ps *PortScanner) Scan(ctx context.Context, host string, ports []int) ([]*pb.Port, error) {
	if len(ports) == 0 {
		ports = Top1000Ports
	}

	ps.logger.Info("starting port scan", "host", host, "ports", len(ports))

	type result struct {
		port *pb.Port
		err  error
	}

	results := make(chan result, len(ports))
	sem := make(chan struct{}, ps.concurrency)

	var wg sync.WaitGroup
	for _, p := range ports {
		select {
		case <-ctx.Done():
			break
		default:
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			state, err := ps.probePort(ctx, host, port)
			if err != nil {
				results <- result{err: err}
				return
			}
			if state == "open" {
				results <- result{port: &pb.Port{
					Number:   int32(port),
					Protocol: "tcp",
					State:    "open",
					Service:  guessService(port),
				}}
			}
		}(p)
	}

	// Close results when all goroutines finish.
	go func() {
		wg.Wait()
		close(results)
	}()

	var open []*pb.Port
	for res := range results {
		if res.err != nil {
			// Non-fatal: individual port errors are expected (filtered/closed).
			continue
		}
		if res.port != nil {
			open = append(open, res.port)
		}
	}

	sort.Slice(open, func(i, j int) bool {
		return open[i].Number < open[j].Number
	})

	ps.logger.Info("port scan complete", "host", host, "open_ports", len(open))
	return open, nil
}

// probePort attempts a TCP connect to host:port and returns "open" or "closed".
func (ps *PortScanner) probePort(ctx context.Context, host string, port int) (string, error) {
	// Respect context deadline but cap at ps.timeout.
	dialCtx := ctx
	if ps.timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, ps.timeout)
		defer cancel()
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		// Any error means the port is closed or filtered.
		return "closed", nil //nolint:nilerr
	}
	conn.Close()
	return "open", nil
}

// guessService returns the common service name for a port number.
func guessService(port int) string {
	if name, ok := portServiceMap[port]; ok {
		return name
	}
	return fmt.Sprintf("port-%d", port)
}
