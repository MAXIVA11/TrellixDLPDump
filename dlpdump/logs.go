package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The agent writes a structured startup/runtime log. Parsing it is the heart of
// "understand how it works": the log narrates which drivers started, how the
// policy was loaded, and whether the agent reached its management server. The
// log is the agent's own account of itself; FTDLP only reads and summarizes it.

const logRoot = `C:\ProgramData\McAfee\DLP\Temp\Logs`

var osWriteFile = os.WriteFile

// LogLine is one parsed entry.
type LogLine struct {
	Time      time.Time `json:"time"`
	Severity  string    `json:"severity"`
	Component string    `json:"component"`
	Location  string    `json:"location,omitempty"`
	Message   string    `json:"message"`
}

var (
	// 2026-10-12 21:32:47.511 [8904] [OERROR] [Agent Service] [Class::method] text
	bracketRe = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) \[\d+\] \[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\]\s*(.*)$`)
	// 2026-... [8904] [STARTUP][AgentService::svc(1089)]> text
	startupRe = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) \[\d+\] \[([A-Z]+)\]\[([^\]]+)\]>\s*(.*)$`)
)

func normSeverity(s string) string {
	s = strings.TrimPrefix(strings.ToUpper(s), "O")
	switch s {
	case "STARTUP", "INFO":
		return "info"
	case "WARNING":
		return "warning"
	case "ERROR":
		return "error"
	default:
		return strings.ToLower(s)
	}
}

func parseLogLine(line string) (LogLine, bool) {
	if m := bracketRe.FindStringSubmatch(line); m != nil {
		t, _ := time.ParseInLocation("2006-01-02 15:04:05.000", m[1], time.Local)
		return LogLine{Time: t, Severity: normSeverity(m[2]), Component: m[3], Location: m[4], Message: strings.TrimSpace(m[5])}, true
	}
	if m := startupRe.FindStringSubmatch(line); m != nil {
		t, _ := time.ParseInLocation("2006-01-02 15:04:05.000", m[1], time.Local)
		return LogLine{Time: t, Severity: normSeverity(m[2]), Component: "Startup", Location: m[3], Message: strings.TrimSpace(m[4])}, true
	}
	return LogLine{}, false
}

func readLog(path string) []LogLine {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []LogLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		if l, ok := parseLogLine(strings.TrimPrefix(sc.Text(), "\ufeff")); ok {
			out = append(out, l)
		}
	}
	return out
}

func newestServiceLog() string {
	dir := filepath.Join(logRoot, "AgentService")
	matches, _ := filepath.Glob(filepath.Join(dir, "HDLP_Service_*.log"))
	sort.Strings(matches)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1]
}

// LogSummary folds a service log into the health picture an admin wants: when
// the agent last started, which drivers it confirmed, how policy loaded,
// management connectivity, and a de-duplicated list of errors/warnings.
type LogSummary struct {
	File         string       `json:"file"`
	Lines        int          `json:"lines"`
	Start        *time.Time   `json:"start,omitempty"`
	Last         *time.Time   `json:"last,omitempty"`
	Drivers      []string     `json:"driver_status"`
	PolicyLoaded string       `json:"policy_loaded"`
	Management   string       `json:"management"`
	Issues       []IssueCount `json:"issues"`
	Subsystems   []string     `json:"subsystems_seen"`
}

// IssueCount collapses a repeated error/warning to one row with a count.
type IssueCount struct {
	Severity  string `json:"severity"`
	Component string `json:"component"`
	Message   string `json:"message"`
	Count     int    `json:"count"`
}

var driverLineRe = regexp.MustCompile(`(hdlp\w+) driver (is running|doesn't running|installed|is installed)`)

func summarizeLog(path string) LogSummary {
	lines := readLog(path)
	s := LogSummary{File: path, Lines: len(lines), PolicyLoaded: "unknown", Management: "unknown"}
	if len(lines) == 0 {
		return s
	}
	s.Start, s.Last = &lines[0].Time, &lines[len(lines)-1].Time

	drv := map[string]string{}
	comps := map[string]bool{}
	type key struct{ sev, comp, msg string }
	issues := map[key]int{}
	var policyOK, policyFail bool

	for _, l := range lines {
		comps[l.Component] = true
		if m := driverLineRe.FindStringSubmatch(l.Message); m != nil {
			state := "running"
			if strings.Contains(m[2], "doesn't") {
				state = "not running"
			} else if strings.Contains(m[2], "installed") {
				if cur, ok := drv[m[1]]; ok && cur == "running" {
					state = "running"
				} else {
					state = "installed (not started)"
				}
			}
			drv[m[1]] = state
		}
		ml := strings.ToLower(l.Message)
		if strings.Contains(ml, "policy") && (strings.Contains(ml, "updat") || strings.Contains(ml, "loaded") || strings.Contains(ml, "enforce")) && l.Severity == "info" {
			policyOK = true
		}
		if strings.Contains(ml, "reading policy") || strings.Contains(ml, "readglobalpolicy") || (strings.Contains(ml, "policy") && l.Severity == "error") {
			policyFail = true
		}
		if strings.Contains(ml, "epo connection information is missing") {
			s.Management = "unmanaged (no ePO server configured)"
		} else if strings.Contains(ml, "connected to epo") || strings.Contains(ml, "epo server details") && l.Severity == "info" {
			s.Management = "managed (ePO)"
		}
		if l.Severity == "error" || l.Severity == "warning" {
			issues[key{l.Severity, l.Component, l.Message}]++
		}
	}

	for _, d := range driverRoles {
		st := drv[d.name]
		if st == "" {
			st = "not mentioned"
		}
		s.Drivers = append(s.Drivers, d.name+": "+st)
	}
	switch {
	case policyOK && !policyFail:
		s.PolicyLoaded = "loaded"
	case policyFail && !policyOK:
		s.PolicyLoaded = "no active policy (none deployed, or load failed)"
	case policyOK && policyFail:
		s.PolicyLoaded = "loaded after earlier errors"
	}
	if s.Management == "unknown" {
		s.Management = "no management info in this log"
	}
	for k, n := range issues {
		s.Issues = append(s.Issues, IssueCount{k.sev, k.comp, k.msg, n})
	}
	sort.Slice(s.Issues, func(a, b int) bool { return s.Issues[a].Count > s.Issues[b].Count })
	for c := range comps {
		s.Subsystems = append(s.Subsystems, c)
	}
	sort.Strings(s.Subsystems)
	return s
}
