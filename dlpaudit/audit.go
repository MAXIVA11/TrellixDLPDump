package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// dlpaudit evaluates how well a Trellix DLP Endpoint deployment is actually
// protecting the machine. It looks for *deployment weaknesses* — a channel left
// uncovered, enforcement not actually running, self-protection off, tampered
// binaries — and reports each with a severity and a remediation. It is a
// hardening/posture auditor, not an exploit or bypass tool, and it is read-only.

type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	return [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[s]
}

// Finding is one audit result.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Pass        bool     `json:"pass"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation,omitempty"`
	sev         Severity `json:"-"`
}

// AuditResult is the whole report.
type AuditResult struct {
	InstallRoot string         `json:"install_root"`
	Computer    string         `json:"computer"`
	AgentVer    string         `json:"agent_version"`
	When        time.Time      `json:"when"`
	Score       int            `json:"posture_score"` // 0..100
	Findings    []Finding      `json:"findings"`
	Counts      map[string]int `json:"counts"`
}

type auditor struct {
	root    string
	cfg     Config
	sys     SystemModel
	log     LogSummary
	logText []LogLine
	mods    []Module
	out     []Finding
}

func (a *auditor) driver(name string) ServiceState {
	for _, d := range a.sys.Drivers {
		if d.Name == name {
			return d.ServiceState
		}
	}
	return ServiceState{Name: name, State: "not-installed"}
}

func (a *auditor) add(id, title string, sev Severity, pass bool, detail, fix string) {
	f := Finding{ID: id, Title: title, Severity: sev.String(), Pass: pass, Detail: detail, sev: sev}
	if !pass {
		f.Remediation = fix
	}
	a.out = append(a.out, f)
}

func onOff(s ServiceState) string { return s.Name + " is " + s.State }

// runChecks is the audit policy: each check is one potential weakness.
func (a *auditor) runChecks() {
	svcRunning := false
	for _, s := range a.sys.Services {
		if s.Name == "TrellixDLPAgentService" && s.State == "running" {
			svcRunning = true
		}
	}

	// --- Enforcement is actually on -----------------------------------------
	a.add("ENF-01", "DLP service is running", SevCritical, svcRunning,
		"TrellixDLPAgentService (fcags.exe) must be running for any enforcement.",
		"Start the service and set it to Automatic; investigate why it is not running.")

	policy := a.cfg.PolicyStore.GlobalPolicySeen
	a.add("ENF-02", "A policy is loaded", SevCritical, policy,
		"No GlobalPolicy.opg was found; an agent with no policy monitors nothing.",
		"Deploy/assign a DLP policy from ePO (or confirm the managed policy reached this host).")

	// --- Channel coverage: each driver maps to an exfil channel -------------
	flt := a.driver("hdlpflt")
	a.add("COV-01", "File / on-access screening active (hdlpflt)", SevCritical, flt.State == "running",
		onOff(flt)+" — the file minifilter screens on-access file content.",
		"Ensure hdlpflt is loaded; without it, file content is not inspected on access.")

	net := a.driver("hdlpnetmonitor")
	a.add("COV-02", "Network DLP active (hdlpnetmonitor)", SevHigh, net.State == "running",
		onOff(net)+" — the WFP callout inspects outbound network traffic.",
		"Load hdlpnetmonitor; otherwise network/web egress is uninspected at the network layer.")

	dbk := a.driver("hdlpdbk")
	a.add("COV-03", "Device / removable-media control active (hdlpdbk)", SevHigh, dbk.State == "running",
		onOff(dbk)+" — device blocking governs USB and other removable media.",
		"If USB/removable control is required, load hdlpdbk and assign a device-control policy.")

	hook := a.driver("hdlphook")
	a.add("COV-04", "User-mode hooks injectable (hdlphook)", SevHigh, hook.State == "running",
		onOff(hook)+" — the injection driver loads the clipboard/print/screen/browser/Outlook hooks.",
		"Load hdlphook; without it, in-application channels (clipboard, print, screenshot, browser) are not watched.")

	ctrl := a.driver("hdlpctrl")
	evnt := a.driver("hdlpevnt")
	a.add("COV-05", "Driver control plane active (hdlpctrl + hdlpevnt)", SevMedium,
		ctrl.State == "running" && evnt.State == "running",
		fmt.Sprintf("%s; %s — these coordinate the drivers and carry events to the service.", onOff(ctrl), onOff(evnt)),
		"Ensure hdlpctrl and hdlpevnt are running so driver events reach the service.")

	// --- Self-protection / tamper resistance --------------------------------
	ap := a.logHas("AccessProtectionObject OK")
	a.add("TMP-01", "Access Protection enabled", SevHigh, ap,
		accessProtDetail(ap),
		"Enable Access Protection so the agent's files, service and registry are protected from tampering.")

	wd := false
	if _, err := os.Stat(filepath.Join(a.root, "fcagswd.exe")); err == nil {
		wd = true
	}
	a.add("TMP-02", "Service watchdog present", SevMedium, wd,
		"fcagswd.exe restarts the agent if it is terminated.",
		"Reinstall/repair the agent; the watchdog binary is missing.")

	up := false
	if _, err := os.Stat(filepath.Join(a.root, "UninstallProtection.exe")); err == nil {
		up = true
	}
	a.add("TMP-03", "Uninstall protection present", SevMedium, up,
		"UninstallProtection.exe blocks unauthorized removal of the agent.",
		"Reinstall/repair the agent; uninstall protection is missing.")

	// Weak ACL on the policy store would let a normal user read/alter policy.
	weakStore := a.cfg.PolicyStore.Readable && a.cfg.PolicyStore.GlobalPolicySeen && storeListable(a.cfg.PolicyStore.Dir)
	a.add("TMP-04", "Policy store is access-protected", SevHigh, !weakStore,
		policyStoreDetail(a.cfg.PolicyStore, weakStore),
		"Restrict the policy store ACL to SYSTEM/administrators so standard users cannot read or modify policy.")

	// --- Binary integrity ---------------------------------------------------
	var tampered []string
	for _, m := range a.mods {
		if m.Signature != nil && m.Signature.Trust == "untrusted" {
			tampered = append(tampered, m.Name)
		}
	}
	a.add("INT-01", "Core binaries are vendor-signed and intact", SevCritical, len(tampered) == 0,
		integrityDetail(tampered),
		"Investigate immediately: an untrusted (broken-signature) binary in the agent may indicate tampering or compromise.")

	// --- Management ----------------------------------------------------------
	a.add("MGT-01", "Agent is centrally managed (ePO)", SevMedium, a.cfg.Managed,
		a.cfg.EpoDetail,
		"An unmanaged agent gets no policy updates or incident collection; connect it to ePO unless standalone operation is intended.")

	// --- Hygiene -------------------------------------------------------------
	age, old := agentBuildAge(a.root)
	a.add("HYG-01", "Agent build is reasonably current", SevLow, !old,
		fmt.Sprintf("Agent %s; newest core binary is ~%d days old.", a.cfg.AgentVersion, age),
		"Review the vendor's release notes/advisories and update if a newer build addresses security fixes.")

	var unsigned []string
	for _, m := range a.mods {
		if m.Signature != nil && m.Signature.Trust == "unsigned" {
			unsigned = append(unsigned, m.Name)
		}
	}
	a.add("HYG-02", "No unexpected unsigned modules", SevInfo, len(unsigned) == 0,
		unsignedDetail(unsigned),
		"Confirm these are the expected bundled third-party libraries (e.g. libprotobuf); unsigned modules are not individually verifiable.")
}

func (a *auditor) logHas(substr string) bool {
	for _, l := range a.logText {
		if strings.Contains(l.Message, substr) {
			return true
		}
	}
	return false
}

func accessProtDetail(on bool) string {
	if on {
		return "The service log shows Access Protection was enabled at startup."
	}
	return "No Access Protection confirmation was found in the agent log; tamper protection may be off."
}

func policyStoreDetail(ps PolicyStoreState, weak bool) string {
	if weak {
		return "The policy store is listable by this (non-SYSTEM) account and contains policy — ACLs are too permissive."
	}
	if ps.Note != "" {
		return "Policy store: " + ps.Note
	}
	return "Policy store is not exposed to standard users."
}

func integrityDetail(tampered []string) string {
	if len(tampered) == 0 {
		return "All verified core executables, drivers and tools carry a valid Trellix (Musarubra) signature."
	}
	return "Untrusted (broken/forged signature) modules: " + strings.Join(tampered, ", ")
}

func unsignedDetail(u []string) string {
	if len(u) == 0 {
		return "No unsigned modules among those checked."
	}
	return fmt.Sprintf("%d unsigned module(s): %s", len(u), strings.Join(u, ", "))
}

// storeListable reports whether the current account can enumerate policy files.
func storeListable(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.HasSuffix(strings.ToLower(e.Name()), ".opg") {
			return true
		}
	}
	return false
}

func agentBuildAge(root string) (days int, old bool) {
	st, err := os.Stat(filepath.Join(root, "fcags.exe"))
	if err != nil {
		return 0, false
	}
	days = int(time.Since(st.ModTime()).Hours() / 24)
	return days, days > 180
}

// score weights failed findings by severity into a 0..100 posture score.
func score(fs []Finding) int {
	weight := map[Severity]int{SevCritical: 30, SevHigh: 18, SevMedium: 8, SevLow: 3, SevInfo: 1}
	maxPts, lost := 0, 0
	for _, f := range fs {
		w := weight[f.sev]
		maxPts += w
		if !f.Pass {
			lost += w
		}
	}
	if maxPts == 0 {
		return 100
	}
	return int(float64(maxPts-lost) / float64(maxPts) * 100)
}

func audit(root string) AuditResult {
	a := &auditor{
		root: root,
		cfg:  gatherConfig(root),
		sys:  systemModel(),
		mods: inventory(root, false),
	}
	if lp := newestServiceLog(); lp != "" {
		a.log = summarizeLog(lp)
		a.logText = readLog(lp)
	}
	a.runChecks()

	res := AuditResult{
		InstallRoot: root,
		Computer:    a.cfg.ComputerName,
		AgentVer:    a.cfg.AgentVersion,
		When:        time.Now(),
		Findings:    a.out,
		Counts:      map[string]int{},
		Score:       score(a.out),
	}
	for _, f := range a.out {
		if !f.Pass {
			res.Counts[f.Severity]++
		}
	}
	return res
}
