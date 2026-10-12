// dlpaudit - a read-only hardening/posture auditor for Trellix (McAfee) DLP
// Endpoint. It reports weaknesses in how the DLP is deployed and configured:
// uncovered egress channels, enforcement not actually running, self-protection
// off, or tampered binaries — each with a severity and a remediation.
//
// It is a defensive posture tool. It is strictly read-only: it never starts,
// stops, disables, uninstalls, reconfigures, exploits or bypasses the agent.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

const usageText = `dlpaudit - read-only hardening auditor for Trellix/McAfee DLP Endpoint

Usage:
  dlpaudit [--json] [--all] [--fail-on critical|high|medium|low]

  --json                machine-readable output
  --all                 show passing checks too (default: failures first, then a pass summary)
  --fail-on <severity>  exit non-zero if any finding at or above this severity failed
                        (default: high)

Read-only: dlpaudit assesses posture. It never changes, disables or bypasses the agent.
`

var toolVersion = "dev"

var sevRank = map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

func main() {
	fs := flag.NewFlagSet("dlpaudit", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	asJSON := fs.Bool("json", false, "JSON output")
	all := fs.Bool("all", false, "show passing checks too")
	failOn := fs.String("fail-on", "high", "exit non-zero at/above this failed severity")
	ver := fs.Bool("version", false, "print version")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *ver {
		fmt.Println("dlpaudit", toolVersion)
		return
	}

	root := discoverInstall()
	if root == "" {
		fmt.Fprintln(os.Stderr, "dlpaudit: no Trellix/McAfee DLP Agent install found under Program Files")
		os.Exit(3)
	}

	res := audit(root)
	// Rank findings: failures first, then by severity desc.
	sort.SliceStable(res.Findings, func(i, j int) bool {
		fi, fj := res.Findings[i], res.Findings[j]
		if fi.Pass != fj.Pass {
			return !fi.Pass
		}
		return sevRank[fi.Severity] > sevRank[fj.Severity]
	})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(res)
	} else {
		render(res, *all)
	}

	threshold := sevRank[strings.ToUpper(*failOn)]
	worst := -1
	for _, f := range res.Findings {
		if !f.Pass && sevRank[f.Severity] >= threshold {
			worst = 1
		}
	}
	if worst == 1 {
		os.Exit(1)
	}
}

func render(r AuditResult, all bool) {
	bar := strings.Repeat("=", 66)
	fmt.Println(bar)
	fmt.Printf(" Trellix DLP Endpoint — posture audit\n")
	fmt.Printf(" Host %s   Agent %s\n", r.Computer, r.AgentVer)
	fmt.Println(bar)

	fails := 0
	for _, f := range r.Findings {
		if !f.Pass {
			fails++
		}
	}
	fmt.Printf(" Posture score: %d/100    %s\n", r.Score, verdict(r.Score))
	fmt.Printf(" Weaknesses:    %s\n\n", countSummary(r.Counts, fails))

	for _, f := range r.Findings {
		if f.Pass && !all {
			continue
		}
		mark := "FAIL"
		if f.Pass {
			mark = "pass"
		}
		fmt.Printf(" [%-4s] %-9s %s  (%s)\n", mark, f.Severity, f.Title, f.ID)
		if !f.Pass || all {
			fmt.Printf("          %s\n", f.Detail)
		}
		if !f.Pass && f.Remediation != "" {
			fmt.Printf("          → fix: %s\n", f.Remediation)
		}
	}

	if !all {
		passed := len(r.Findings) - fails
		fmt.Printf("\n %d checks passed (run with --all to list them).\n", passed)
	}
}

func verdict(score int) string {
	switch {
	case score >= 90:
		return "strong"
	case score >= 70:
		return "adequate, with gaps"
	case score >= 40:
		return "weak — several exposures"
	default:
		return "critical — the control is largely ineffective"
	}
}

func countSummary(counts map[string]int, fails int) string {
	if fails == 0 {
		return "none — all checks passed"
	}
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	var parts []string
	for _, s := range order {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return strings.Join(parts, ", ")
}
