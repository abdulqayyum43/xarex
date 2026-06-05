// Package scanner — Nuclei templated vulnerability scanner.
//
// Wraps the upstream `nuclei` binary (Apache 2.0, projectdiscovery.io) so
// Xarex inherits the entire community template library (~9,000 templates
// covering CVEs, misconfigurations, exposed panels, default credentials,
// tech detection, etc.) without re-implementing the YAML rule engine.
//
// Design notes:
//   - We shell out via os/exec. The binary path is configurable via the
//     XAREX_NUCLEI_BIN env var so deployments can pin a specific version.
//   - We feed nuclei a single URL per task (not a list) so the cloud-brain
//     pipeline keeps one finding-stream per target/port. The Cloud Brain
//     fans out across hosts and ports already.
//   - Templates are auto-installed in the probe Docker image at build time
//     (`nuclei -update-templates`). We never auto-update at runtime —
//     reproducible scans are more important than fresh rules.
//   - JSON output (`-j`) is parsed line-by-line; each match becomes one
//     pb.Finding. Severity strings ("info", "low", ..., "critical") map to
//     the existing pb.Severity enum.

package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xarex/probe/grpc/pb"
)

const (
	defaultNucleiBin       = "/usr/local/bin/nuclei"
	defaultNucleiTemplates = "/opt/nuclei-templates"
	defaultNucleiTimeout   = 4 * time.Minute
)

// NucleiScanner runs the upstream nuclei binary against a single URL.
type NucleiScanner struct {
	logger    *slog.Logger
	bin       string
	templates string
}

// NewNucleiScanner returns a NucleiScanner using $XAREX_NUCLEI_BIN +
// $XAREX_NUCLEI_TEMPLATES, falling back to the install locations baked into
// the probe Docker image.
func NewNucleiScanner(logger *slog.Logger) *NucleiScanner {
	bin := os.Getenv("XAREX_NUCLEI_BIN")
	if bin == "" {
		bin = defaultNucleiBin
	}
	tpls := os.Getenv("XAREX_NUCLEI_TEMPLATES")
	if tpls == "" {
		tpls = defaultNucleiTemplates
	}
	return &NucleiScanner{logger: logger, bin: bin, templates: tpls}
}

// nucleiJSON is a subset of nuclei's `-j` line schema. We only deserialise
// the fields we surface — keeps us resilient to upstream schema additions.
type nucleiJSON struct {
	TemplateID   string `json:"template-id"`
	TemplateURL  string `json:"template-url"`
	Type         string `json:"type"`
	Host         string `json:"host"`
	MatchedAt    string `json:"matched-at"`
	Request      string `json:"request"`
	Response     string `json:"response"`
	ExtractedRes string `json:"extracted-results"`
	Info         struct {
		Name        string   `json:"name"`
		Author      []string `json:"author"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Reference   []string `json:"reference"`
		Tags        []string `json:"tags"`
		Classification struct {
			CVEID []string `json:"cve-id"`
			CWEID []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
}

// severityFromString maps nuclei's severity strings to pb.Severity.
// nuclei recognises: info, low, medium, high, critical, unknown.
func severityFromString(s string) pb.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return pb.Severity_CRITICAL
	case "high":
		return pb.Severity_HIGH
	case "medium":
		return pb.Severity_MEDIUM
	case "low":
		return pb.Severity_LOW
	default:
		return pb.Severity_INFO
	}
}

func truncateNuclei(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// sanitizeForPostgres strips NUL bytes (\x00). Nuclei response capture can
// include raw binary bytes when matching against TCP services like Redis
// or memcached, and Postgres rejects NUL bytes in text columns
// (CharacterNotInRepertoireError). Without this the entire batch insert
// fails atomically and ALL findings from the task get dropped.
func sanitizeForPostgres(s string) string {
	if !strings.ContainsRune(s, '\x00') {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

// Scan runs nuclei against `target` (a fully-qualified URL like
// "http://example.com:8080" or "https://example.com") and returns each
// match as a pb.Finding.
//
// Resource budget enforced via the upstream binary's own flags:
//   -timeout 5    (per-request timeout, seconds)
//   -c 25         (concurrent templates)
//   -rl 100       (requests per second cap)
//   -ni           (no interactive prompts)
//
// The whole invocation is wrapped in a context with `defaultNucleiTimeout`
// so a single hung target can't tie up a probe forever.
func (n *NucleiScanner) Scan(ctx context.Context, target string) ([]*pb.Finding, error) {
	if _, err := os.Stat(n.bin); err != nil {
		return nil, fmt.Errorf("nuclei binary not found at %s — set XAREX_NUCLEI_BIN", n.bin)
	}

	scanCtx, cancel := context.WithTimeout(ctx, defaultNucleiTimeout)
	defer cancel()

	args := []string{
		"-u", target,
		// Explicit templates path — nuclei silently runs zero templates when
		// it can't find them, and the env-var fallback ($NUCLEI_TEMPLATES_DIR)
		// is unreliable across Docker setups. Pass -t explicitly so a fresh
		// container always has the full library to work with.
		"-t", n.templates,
		"-j",          // JSON output (newline-delimited)
		"-silent",     // no banner
		"-nc",         // no color
		"-disable-update-check",
		"-ni",         // no interactive prompts
		"-timeout", "5",
		"-c", "25",
		"-rl", "100",
		// Include info-level matches: many of them are valuable tech-detection
		// signals (e.g. "exposed git directory", "Apache server-status",
		// "Joomla X.Y detected") that drive the autonomous engine's next steps
		// and are demoable in their own right. Customers can filter UI-side.
		"-severity", "info,low,medium,high,critical",
		"-duc", // disable upstream update check — we manage versions in Docker
	}

	n.logger.Info("starting nuclei scan", "target", target, "bin", n.bin)

	cmd := exec.CommandContext(scanCtx, n.bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("nuclei stdout pipe: %w", err)
	}
	// Pipe stderr to our logger at debug — useful for "no internet, can't
	// fetch templates" diagnostics without polluting the result stream.
	stderrPipe, _ := cmd.StderrPipe()
	go func() {
		if stderrPipe == nil {
			return
		}
		s := bufio.NewScanner(stderrPipe)
		for s.Scan() {
			n.logger.Debug("nuclei stderr", "line", s.Text())
		}
	}()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("nuclei start: %w", err)
	}

	var findings []*pb.Finding
	scanner := bufio.NewScanner(stdout)
	// Some nuclei lines can be > 64KB (response body inclusion). Bump the
	// buffer so we don't truncate mid-line and lose findings.
	scanner.Buffer(make([]byte, 0, 1<<20), 4<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var nj nucleiJSON
		if err := json.Unmarshal(line, &nj); err != nil {
			n.logger.Debug("nuclei json parse failed", "error", err)
			continue
		}

		title := nj.Info.Name
		if title == "" {
			title = nj.TemplateID
		}
		desc := nj.Info.Description
		if desc == "" {
			desc = fmt.Sprintf("Template %s matched on %s", nj.TemplateID, nj.MatchedAt)
		}

		// Compose evidence — keep response body short to avoid bloating the
		// gRPC message + DB row.
		evidence := strings.Builder{}
		if nj.MatchedAt != "" {
			evidence.WriteString("Matched at: " + nj.MatchedAt + "\n")
		}
		if len(nj.Info.Reference) > 0 {
			evidence.WriteString("Reference:  " + strings.Join(nj.Info.Reference, ", ") + "\n")
		}
		if nj.Request != "" {
			evidence.WriteString("\n--- Request ---\n")
			evidence.WriteString(truncateNuclei(nj.Request, 600))
		}
		if nj.Response != "" {
			evidence.WriteString("\n\n--- Response ---\n")
			evidence.WriteString(truncateNuclei(nj.Response, 800))
		}
		if nj.ExtractedRes != "" {
			evidence.WriteString("\n\n--- Extracted ---\n" + truncateNuclei(nj.ExtractedRes, 200))
		}

		cveID := ""
		if len(nj.Info.Classification.CVEID) > 0 {
			cveID = strings.ToUpper(nj.Info.Classification.CVEID[0])
		}

		metadata := map[string]string{
			"template_id": nj.TemplateID,
			"matched_at":  nj.MatchedAt,
			"type":        nj.Type,
		}
		if len(nj.Info.Tags) > 0 {
			metadata["tags"] = strings.Join(nj.Info.Tags, ",")
		}
		if nj.TemplateURL != "" {
			metadata["template_url"] = nj.TemplateURL
		}

		findings = append(findings, &pb.Finding{
			FindingId:   uuid.NewString(),
			Host:        sanitizeForPostgres(nj.Host),
			Protocol:    "tcp",
			Service:     "nuclei",
			Severity:    severityFromString(nj.Info.Severity),
			CveId:       cveID,
			Title:       sanitizeForPostgres(title),
			Description: sanitizeForPostgres(desc),
			Evidence:    sanitizeForPostgres(evidence.String()),
			Remediation: sanitizeForPostgres("See template reference: " + strings.Join(nj.Info.Reference, ", ")),
			Metadata:    metadata,
			Timestamp:   time.Now().UnixMilli(),
		})
	}

	// Wait for the binary to exit so we surface exit-code errors. Nuclei
	// returns 0 on success even with no findings; non-zero usually means
	// "couldn't reach target" or "template directory missing".
	waitErr := cmd.Wait()
	if waitErr != nil {
		if scanCtx.Err() == context.DeadlineExceeded {
			n.logger.Warn("nuclei timed out", "target", target)
			return findings, fmt.Errorf("nuclei timed out after %s", defaultNucleiTimeout)
		}
		// Don't treat exit code 1 as fatal — nuclei uses it for "no match"
		// in some versions. Log and return whatever findings we collected.
		n.logger.Debug("nuclei exit", "error", waitErr)
	}

	n.logger.Info("nuclei scan complete", "target", target, "findings", len(findings))
	return findings, nil
}
