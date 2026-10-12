package main

import (
	"os"
	"path/filepath"
	"strings"
)

// The DLP drivers and what each one enforces. Names and descriptions are from
// each .sys file's version resource; the role note explains the mechanism.
var driverRoles = []struct{ name, note string }{
	{"hdlpflt", "mini-filter: file-system interception for on-access content scanning"},
	{"hdlpdbk", "device blocking: removable-storage and device-class control"},
	{"hdlpnetmonitor", "WFP network callout: outbound/network DLP"},
	{"hdlphook", "injection driver (madCodeHook) that loads the user-mode hooks into processes"},
	{"hdlpctrl", "controller: coordinates the other drivers with the service"},
	{"hdlpevnt", "event manager: carries driver events up to the agent"},
}

// Services FTDLP reports on.
var serviceNames = []string{"TrellixDLPAgentService", "macmnsvc", "masvc", "mfemms"}

// SystemModel is the live OS-level view of the deployment.
type SystemModel struct {
	Services []ServiceState `json:"services"`
	Drivers  []DriverView   `json:"drivers"`
}

// DriverView pairs a driver's live SCM state with its role.
type DriverView struct {
	ServiceState
	Role string `json:"role"`
}

func systemModel() SystemModel {
	var m SystemModel
	for _, n := range serviceNames {
		s := queryService(n)
		if s.found || n == "TrellixDLPAgentService" {
			m.Services = append(m.Services, s)
		}
	}
	for _, d := range driverRoles {
		m.Drivers = append(m.Drivers, DriverView{ServiceState: queryService(d.name), Role: d.note})
	}
	return m
}

// --- Configuration & management state ---------------------------------------

const regAgent = `SOFTWARE\McAfee\DLP\Agent`

// Config is the agent's management and policy state, read from the registry
// and the policy store on disk.
type Config struct {
	AgentVersion   string            `json:"agent_version"`
	ComputerName   string            `json:"computer_name"`
	InstallDir     string            `json:"install_dir"`
	InstalledHdlrs string            `json:"installed_handlers"`
	Managed        bool              `json:"managed_by_epo"`
	EpoDetail      string            `json:"epo_detail"`
	PolicyStore    PolicyStoreState  `json:"policy_store"`
	Registry       map[string]string `json:"registry"`
}

// PolicyStoreState describes the on-disk policy without needing its contents.
type PolicyStoreState struct {
	Dir              string `json:"dir"`
	Readable         bool   `json:"readable_by_current_user"`
	GlobalPolicySeen bool   `json:"global_policy_present"`
	Note             string `json:"note"`
}

const epoAgentKey = `SOFTWARE\Network Associates\ePolicy Orchestrator\Agent`

func gatherConfig(installRoot string) Config {
	c := Config{
		AgentVersion: regString(regAgent, "AgentVersion"),
		ComputerName: regString(regAgent+`\Properties\General`, "ComputerName"),
		InstallDir:   regString(regAgent, "InstDir"),
		Registry:     regValues(regAgent),
	}
	c.InstalledHdlrs = c.Registry["InstalledHandlers"]
	guid := regString(epoAgentKey, "AgentGUID")
	online := c.Registry["AgentOnline"]
	switch {
	case guid != "":
		c.Managed, c.EpoDetail = true, "ePO AgentGUID present; online flag="+online
	default:
		c.Managed = false
		c.EpoDetail = "no ePO AgentGUID in registry (unmanaged / standalone); AgentOnline=" + online
	}

	store := filepath.Join(`C:\ProgramData\McAfee\DLP\Agent\Policy`)
	ps := PolicyStoreState{Dir: store}
	if entries, err := os.ReadDir(store); err == nil {
		ps.Readable = true
		for _, e := range entries {
			if strings.HasSuffix(strings.ToLower(e.Name()), ".opg") {
				ps.GlobalPolicySeen = true
			}
		}
		if len(entries) == 0 {
			ps.Note = "directory is empty or its entries are hidden from this account"
		}
	} else {
		ps.Note = "not listable by this account: " + errText(err)
	}
	// The running policy is cached under Temp\Policy as GlobalPolicy.opg.
	if _, err := os.Stat(`C:\ProgramData\McAfee\DLP\Temp\Policy\GlobalPolicy.opg`); err == nil {
		ps.GlobalPolicySeen = true
	}
	c.PolicyStore = ps
	return c
}

func errText(err error) string {
	if os.IsPermission(err) {
		return "access denied"
	}
	return err.Error()
}
