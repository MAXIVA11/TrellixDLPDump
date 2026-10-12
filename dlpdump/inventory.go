package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// The install is hundreds of files. FTDLP groups them into the subsystems that
// make up the agent, so the report explains the product rather than listing
// DLLs. Classification is by filename and extension, corroborated by the
// version resource's FileDescription.

type Role string

const (
	RoleCore     Role = "core"           // agent services & executables
	RoleDriver   Role = "kernel-driver"  // hdlp*.sys
	RoleHook     Role = "app-hook"       // browser / Office injection modules
	RoleKeyView  Role = "content-filter" // KeyView format readers (content inspection)
	RoleOCR      Role = "ocr"            // optical character recognition
	RoleCrypto   Role = "crypto-rms"     // encryption / Microsoft Information Protection
	RoleIdentity Role = "identity"       // Entra / MSAL auth
	RoleSupport  Role = "support-lib"    // everything else
	RoleTool     Role = "admin-tool"     // Tools\ diagnostics
)

var roleDesc = map[Role]string{
	RoleCore:     "Agent services, watchdog and host processes",
	RoleDriver:   "Kernel-mode drivers (file, device, network, injection, events)",
	RoleHook:     "User-mode hooks injected into browsers and Office to see content before it leaves",
	RoleKeyView:  "KeyView filters that crack open ~400 file formats to read their text for classification",
	RoleOCR:      "OCR engine for reading text inside images",
	RoleCrypto:   "Encryption and Microsoft Information Protection / RMS integration",
	RoleIdentity: "Microsoft Entra / MSAL identity for user and tenant resolution",
	RoleSupport:  "Shared runtime and support libraries",
	RoleTool:     "Vendor diagnostic tools",
}

// Module is one classified file in the install.
type Module struct {
	Name        string     `json:"name"`
	Dir         string     `json:"dir,omitempty"`
	Role        Role       `json:"role"`
	SizeKB      int64      `json:"size_kb"`
	Description string     `json:"description,omitempty"`
	Version     string     `json:"version,omitempty"`
	Signature   *Signature `json:"signature,omitempty"`
	path        string
}

func classify(name string) Role {
	l := strings.ToLower(name)
	ext := filepath.Ext(l)
	switch {
	case ext == ".sys":
		return RoleDriver
	case ext == ".exe":
		return RoleCore
	case strings.Contains(l, "chrome"), strings.Contains(l, "ff64"), l == "fcagff.dll",
		strings.Contains(l, "iep"), strings.Contains(l, "ie32"), strings.Contains(l, "ie64"),
		strings.Contains(l, "olh"), strings.Contains(l, "pph"), strings.Contains(l, "cbh"),
		strings.Contains(l, "cfh"), strings.Contains(l, "clh"), strings.Contains(l, "sch"),
		strings.Contains(l, "afa"), strings.Contains(l, "plie"), strings.Contains(l, "mtph"):
		return RoleHook
	case strings.HasSuffix(l, "sr.dll"), strings.HasPrefix(l, "kp") && strings.HasSuffix(l, "rdr.dll"),
		strings.HasPrefix(l, "kv"), l == "keyviewfilter.dll", strings.HasPrefix(l, "filter"):
		return RoleKeyView
	case strings.HasPrefix(l, "ocr"):
		return RoleOCR
	case strings.HasPrefix(l, "mip_"), strings.Contains(l, "cryptograph"), l == "fips.dll",
		strings.Contains(l, "crypto"), strings.Contains(l, "titus"), strings.HasPrefix(l, "libcrypto"):
		return RoleCrypto
	case strings.Contains(l, "identity"), strings.Contains(l, "msal"), strings.Contains(l, "entra"),
		strings.Contains(l, "azureauth"), strings.Contains(l, "acquiremsal"):
		return RoleIdentity
	default:
		return RoleSupport
	}
}

// Known core executables, so the report names their job even if the version
// resource is terse. Values confirmed from each binary's FileDescription.
var coreRoleNote = map[string]string{
	"fcags.exe":               "main DLP service (SCM: TrellixDLPAgentService)",
	"fcag.exe":                "per-session agent / enforcement UI host",
	"fcagswd.exe":             "service watchdog (restarts the agent if killed)",
	"fcagd.exe":               "diagnostics",
	"fcagte.exe":              "text extractor (feeds KeyView/OCR)",
	"fcpm.exe":                "performance monitor",
	"fcom.exe":                "Outlook monitor",
	"fcnm.exe":                "browser native-messaging host",
	"fcnmtub.exe":             "browser native-messaging host (tab)",
	"fcpst.exe":               "email/PST storage crawler",
	"UninstallProtection.exe": "tamper / uninstall protection",
}

func discoverInstall() string {
	for _, p := range []string{
		`C:\Program Files\McAfee\DLP\Agent`,
		`C:\Program Files\Trellix\DLP\Agent`,
		`C:\Program Files (x86)\McAfee\DLP\Agent`,
	} {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return ""
}

// inventory classifies every file under the install root. Signatures are
// verified for core executables, drivers and tools always; deep adds the rest.
func inventory(root string, deep bool) []Module {
	var mods []Module
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".exe" && ext != ".dll" && ext != ".sys" {
			return nil
		}
		info, _ := d.Info()
		role := classify(d.Name())
		if strings.Contains(strings.ToLower(p), `\tools\`) && ext == ".exe" {
			role = RoleTool
		}
		m := Module{Name: d.Name(), Role: role, path: p}
		if rel, err := filepath.Rel(root, filepath.Dir(p)); err == nil && rel != "." {
			m.Dir = rel
		}
		if info != nil {
			m.SizeKB = info.Size() / 1024
		}
		mods = append(mods, m)
		return nil
	})

	verifyAll := deep
	type job struct{ i int }
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				m := &mods[i]
				vi := readVersionInfo(m.path)
				m.Description = vi.FileDescription
				m.Version = vi.ProductVersion
				if note, ok := coreRoleNote[m.Name]; ok {
					m.Description = note
				}
				if verifyAll || m.Role == RoleCore || m.Role == RoleDriver || m.Role == RoleTool {
					s := verifySignature(m.path)
					m.Signature = &s
				}
			}
		}()
	}
	for i := range mods {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	sort.Slice(mods, func(a, b int) bool {
		if mods[a].Role != mods[b].Role {
			return mods[a].Role < mods[b].Role
		}
		return strings.ToLower(mods[a].Name) < strings.ToLower(mods[b].Name)
	})
	return mods
}
