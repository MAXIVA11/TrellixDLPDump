package main

import (
	"strings"
	"testing"
)

// Verbatim lines from the agent's own service log on the development machine,
// covering both log grammars (bracketed component lines and STARTUP lines).
const sampleLog = `2026-10-12 21:32:47.509 [8904] [STARTUP][AgentService::checkSoftwareDriver(1036)]> hdlpevnt driver is running
2026-10-12 21:32:47.509 [8904] [STARTUP][AgentService::checkSoftwareDriver(1036)]> hdlpctrl driver is running
2026-10-12 21:32:47.509 [8904] [STARTUP][AgentService::checkSoftwareDriver(1040)]> hdlpnetmonitor driver doesn't running, check if installed
2026-10-12 21:32:47.511 [8904] [STARTUP][AgentService::runSelfRemediation(920)]> hdlpflt driver is running
2026-10-12 21:32:47.511 [8904] [STARTUP][AgentService::checkDeviceClassDriver(991)]> hdlpdbk driver is installed
2026-10-12 21:32:47.511 [8904] [OERROR] [Agent Service] [PolicyDispatcher::readGlobalPolicy]  globalPolicyFileHandler.open failed
2026-10-12 21:32:51.960 [8904] [OWARNING] [System Configuration Manager] [CheckConnectivity::checkConnectionStateMachine] ePO connection information is missing.
2026-10-12 21:33:21.978 [29672] [OWARNING] [System Configuration Manager] [CheckConnectivity::checkConnectionStateMachine] ePO connection information is missing.
2026-10-12 21:32:55.518 [8904] [STARTUP][AgentService::enableDisableAccessProtection(674)]> AccessProtectionObject OK!
`

func TestParseGrammars(t *testing.T) {
	info, _ := parseLogLine(`2026-10-12 21:32:47.509 [8904] [STARTUP][AgentService::checkSoftwareDriver(1036)]> hdlpevnt driver is running`)
	if info.Severity != "info" || info.Component != "Startup" || !strings.Contains(info.Message, "hdlpevnt") {
		t.Errorf("startup line parsed as %+v", info)
	}
	e, _ := parseLogLine(`2026-10-12 21:32:47.511 [8904] [OERROR] [Agent Service] [PolicyDispatcher::readGlobalPolicy]  globalPolicyFileHandler.open failed`)
	if e.Severity != "error" || e.Component != "Agent Service" {
		t.Errorf("bracket line parsed as %+v", e)
	}
	if _, ok := parseLogLine("not a log line"); ok {
		t.Error("non-log line accepted")
	}
}

func TestSummarizeFromLines(t *testing.T) {
	path := t.TempDir() + `\svc.log`
	if err := writeFile(path, sampleLog); err != nil {
		t.Fatal(err)
	}
	s := summarizeLog(path)
	if s.Management != "unmanaged (no ePO server configured)" {
		t.Errorf("management = %q", s.Management)
	}
	if !strings.Contains(s.PolicyLoaded, "no active policy") {
		t.Errorf("policy = %q", s.PolicyLoaded)
	}
	drv := strings.Join(s.Drivers, " | ")
	for _, want := range []string{"hdlpevnt: running", "hdlpnetmonitor: not running", "hdlpdbk: installed (not started)"} {
		if !strings.Contains(drv, want) {
			t.Errorf("driver status %q missing from %q", want, drv)
		}
	}
	// The two identical ePO warnings must collapse to one row with count 2.
	var epo *IssueCount
	for i := range s.Issues {
		if strings.Contains(s.Issues[i].Message, "ePO connection") {
			epo = &s.Issues[i]
		}
	}
	if epo == nil || epo.Count != 2 {
		t.Errorf("ePO warning not collapsed: %+v", epo)
	}
}

func writeFile(path, content string) error {
	return osWriteFile(path, []byte(content), 0o644)
}
