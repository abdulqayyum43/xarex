package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"
)

// TestSSLAudit_RealWorld runs the SSL auditor against badssl.com test endpoints
// (intentionally misconfigured for testing) and a few real-world targets.
//
// Run: go test ./scanner/ -run TestSSLAudit_RealWorld -v -timeout 120s
func TestSSLAudit_RealWorld(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s := NewSSLAuditScanner(logger)

	targets := []struct {
		host         string
		port         int
		expectTitles []string // substrings we expect to see in finding titles
		note         string
	}{
		{
			host:         "expired.badssl.com",
			port:         443,
			expectTitles: []string{"Expired", "expir"},
			note:         "Expired certificate — should flag cert expiry",
		},
		{
			host:         "self-signed.badssl.com",
			port:         443,
			expectTitles: []string{"Self-Signed", "self"},
			note:         "Self-signed cert — should flag untrusted chain",
		},
		{
			host:         "wrong.host.badssl.com",
			port:         443,
			expectTitles: []string{"Hostname", "mismatch"},
			note:         "Hostname mismatch — common.name != host",
		},
		{
			host:         "tls-v1-0.badssl.com",
			port:         443,
			expectTitles: []string{"TLS 1.0"},
			note:         "TLS 1.0 enabled — deprecated protocol",
		},
		{
			host:         "sha256.badssl.com",
			port:         443,
			expectTitles: []string{},
			note:         "Good SHA-256 cert — baseline clean target",
		},
	}

	totalFindings := 0

	for _, tt := range targets {
		t.Run(fmt.Sprintf("%s:%d", tt.host, tt.port), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			fmt.Printf("TARGET : %s:%d\n", tt.host, tt.port)
			fmt.Printf("NOTE   : %s\n", tt.note)
			fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

			findings, err := s.Audit(ctx, tt.host, tt.port)
			if err != nil {
				t.Logf("audit error (may be expected for broken targets): %v", err)
			}

			totalFindings += len(findings)

			sevLabels := []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
			counts := map[int]int{}
			for _, f := range findings {
				counts[f.Severity]++
				sev := "INFO"
				if f.Severity < len(sevLabels) {
					sev = sevLabels[f.Severity]
				}
				cve := ""
				if f.CVEID != "" {
					cve = fmt.Sprintf(" [%s]", f.CVEID)
				}
				fmt.Printf("  [%s]%s %s\n", sev, cve, f.Title)
				if f.Evidence != "" {
					fmt.Printf("    Evidence    : %s\n", truncateStr(f.Evidence, 100))
				}
				fmt.Printf("    Remediation : %s\n", truncateStr(f.Remediation, 100))
			}

			if len(findings) == 0 {
				fmt.Println("  (no findings — target is clean or unreachable)")
			} else {
				fmt.Printf("\n  Summary: %d finding(s) — ", len(findings))
				for sev, label := range sevLabels {
					if n := counts[sev]; n > 0 {
						fmt.Printf("%s:%d ", label, n)
					}
				}
				fmt.Println()
			}
		})
	}

	fmt.Printf("\n═══════════════════════════════════════════════\n")
	fmt.Printf("TOTAL FINDINGS ACROSS ALL TARGETS: %d\n", totalFindings)
	fmt.Printf("═══════════════════════════════════════════════\n")
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
