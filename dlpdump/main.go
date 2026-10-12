// dlpdump - a read-only inspector / dumper for a Trellix (McAfee) DLP Endpoint
// deployment. It reports what is installed (grouped by subsystem, with
// Authenticode verification), the live state of the services and kernel
// drivers, the management/policy state, and a health summary parsed from the
// agent's own log.
//
// It is strictly read-only: it never starts, stops, disables, uninstalls or
// reconfigures the agent, and it does not read protected policy content. It is
// a diagnostics and understanding tool, not a control tool.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

const usageText = `dlpdump - read-only inspector for Trellix/McAfee DLP Endpoint

Usage:
  dlpdump [--format text|md|json] [--deep]

  --format text   human-readable report (default)
  --format md     Markdown component catalog + state (great for docs/issues)
  --format json   machine-readable
  --deep          verify the Authenticode signature of every module (slower)

Read-only: dlpdump never starts, stops, disables or reconfigures the agent.
`

var toolVersion = "dev"

// Report is the full dump.
type Report struct {
	InstallRoot string      `json:"install_root"`
	Tool        string      `json:"tool_version"`
	Config      Config      `json:"config"`
	System      SystemModel `json:"system"`
	Health      LogSummary  `json:"health"`
	Modules     []Module    `json:"modules"`
}

func main() {
	fs := flag.NewFlagSet("dlpdump", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	format := fs.String("format", "text", "text | md | json")
	deep := fs.Bool("deep", false, "verify every module signature")
	ver := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *ver {
		fmt.Println("dlpdump", toolVersion)
		return
	}

	root := discoverInstall()
	if root == "" {
		fmt.Fprintln(os.Stderr, "dlpdump: no Trellix/McAfee DLP Agent install found under Program Files")
		os.Exit(3)
	}

	rep := Report{
		InstallRoot: root,
		Tool:        toolVersion,
		Config:      gatherConfig(root),
		System:      systemModel(),
		Modules:     inventory(root, *deep),
	}
	if lp := newestServiceLog(); lp != "" {
		rep.Health = summarizeLog(lp)
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
	case "md":
		fmt.Print(renderMarkdown(rep))
	case "text":
		renderText(rep)
	default:
		fmt.Fprintf(os.Stderr, "dlpdump: unknown format %q\n", *format)
		os.Exit(2)
	}
}

// --- grouping helper shared by both renderers -------------------------------

var roleOrder = []Role{RoleCore, RoleDriver, RoleHook, RoleCrypto, RoleIdentity, RoleOCR, RoleKeyView, RoleTool, RoleSupport}

func groupByRole(mods []Module) map[Role][]Module {
	m := map[Role][]Module{}
	for _, x := range mods {
		m[x.Role] = append(m[x.Role], x)
	}
	return m
}

func trustCounts(mods []Module) (map[string]int, int) {
	c := map[string]int{}
	n := 0
	for _, m := range mods {
		if m.Signature != nil {
			c[m.Signature.Trust]++
			n++
		}
	}
	return c, n
}

func sigCell(m Module) string {
	if m.Signature == nil {
		return ""
	}
	if m.Signature.Trust == "trusted" {
		if m.Signature.Signer != "" {
			return m.Signature.Signer
		}
		return "trusted"
	}
	s := strings.ToUpper(m.Signature.Trust)
	if m.Signature.Detail != "" {
		s += " (" + m.Signature.Detail + ")"
	}
	return s
}

func kb(n int64) string {
	if n >= 1024 {
		return fmt.Sprintf("%d MB", n/1024)
	}
	return fmt.Sprintf("%d KB", n)
}
