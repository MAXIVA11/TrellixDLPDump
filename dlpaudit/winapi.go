package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	version  = syscall.NewLazyDLL("version.dll")

	procGetFileVersionInfoSizeW = version.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW     = version.NewProc("GetFileVersionInfoW")
	procVerQueryValueW          = version.NewProc("VerQueryValueW")

	procOpenSCManagerW   = advapi32.NewProc("OpenSCManagerW")
	procOpenServiceW     = advapi32.NewProc("OpenServiceW")
	procQueryServiceStat = advapi32.NewProc("QueryServiceStatusEx")
	procQueryServiceCfg  = advapi32.NewProc("QueryServiceConfigW")
	procCloseServiceH    = advapi32.NewProc("CloseServiceHandle")
	procRegEnumValueW    = advapi32.NewProc("RegEnumValueW")
)

func utf16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

// --- Version resource reader -------------------------------------------------

// VersionInfo holds the fields FTDLP reports from a PE's version resource.
type VersionInfo struct {
	FileDescription string
	ProductName     string
	ProductVersion  string
	CompanyName     string
}

func readVersionInfo(path string) VersionInfo {
	var vi VersionInfo
	var handle uintptr
	size, _, _ := procGetFileVersionInfoSizeW.Call(uintptr(unsafe.Pointer(utf16(path))), uintptr(unsafe.Pointer(&handle)))
	if size == 0 {
		return vi
	}
	buf := make([]byte, size)
	if r, _, _ := procGetFileVersionInfoW.Call(uintptr(unsafe.Pointer(utf16(path))), 0, size, uintptr(unsafe.Pointer(&buf[0]))); r == 0 {
		return vi
	}
	// Translation table: first language/codepage pair.
	var trans unsafe.Pointer
	var tlen uint32
	if r, _, _ := procVerQueryValueW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(utf16(`\VarFileInfo\Translation`))), uintptr(unsafe.Pointer(&trans)), uintptr(unsafe.Pointer(&tlen))); r == 0 || tlen < 4 {
		return vi
	}
	pair := (*[2]uint16)(trans)
	prefix := fmt.Sprintf(`\StringFileInfo\%04x%04x\`, pair[0], pair[1])
	get := func(field string) string {
		var val unsafe.Pointer
		var vlen uint32
		if r, _, _ := procVerQueryValueW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(utf16(prefix+field))), uintptr(unsafe.Pointer(&val)), uintptr(unsafe.Pointer(&vlen))); r == 0 || vlen == 0 {
			return ""
		}
		return syscall.UTF16ToString((*[4096]uint16)(val)[:vlen])
	}
	vi.FileDescription = get("FileDescription")
	vi.ProductName = get("ProductName")
	vi.ProductVersion = get("ProductVersion")
	vi.CompanyName = get("CompanyName")
	return vi
}

// --- Service control manager (read-only) ------------------------------------

const (
	scManagerConnect    = 0x0001
	scManagerEnumerate  = 0x0004
	serviceQueryStatus  = 0x0004
	serviceQueryConfig  = 0x0001
	scStatusProcessInfo = 0
)

var stateNames = map[uint32]string{1: "stopped", 2: "start-pending", 3: "stop-pending", 4: "running", 5: "continue-pending", 6: "pause-pending", 7: "paused"}
var startNames = map[uint32]string{0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}

// ServiceState is the live SCM view of one service or driver.
type ServiceState struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	StartType string `json:"start_type"`
	PID       uint32 `json:"pid,omitempty"`
	ImagePath string `json:"image_path,omitempty"`
	found     bool
}

func queryService(name string) ServiceState {
	s := ServiceState{Name: name, State: "not-installed"}
	scm, _, e := procOpenSCManagerW.Call(0, 0, scManagerConnect|scManagerEnumerate)
	if scm == 0 {
		s.State = "scm-open-failed: " + e.Error()
		return s
	}
	defer procCloseServiceH.Call(scm)
	h, _, e := procOpenServiceW.Call(scm, uintptr(unsafe.Pointer(utf16(name))), serviceQueryStatus|serviceQueryConfig)
	if h == 0 {
		if en, ok := e.(syscall.Errno); ok && en == 1060 { // ERROR_SERVICE_DOES_NOT_EXIST
			return s
		}
		s.State = "query-failed: " + e.Error()
		return s
	}
	defer procCloseServiceH.Call(h)
	s.found = true
	s.State = "installed"

	var status struct {
		Type, CurrentState, Controls, Win32Exit, SvcExit, CheckPoint, WaitHint, ProcessId, ServiceFlags uint32
	}
	var need uint32
	if r, _, _ := procQueryServiceStat.Call(h, scStatusProcessInfo, uintptr(unsafe.Pointer(&status)), unsafe.Sizeof(status), uintptr(unsafe.Pointer(&need))); r != 0 {
		s.State = name2(stateNames, status.CurrentState)
		s.PID = status.ProcessId
	}
	cfgBuf := make([]byte, 8192)
	if r, _, _ := procQueryServiceCfg.Call(h, uintptr(unsafe.Pointer(&cfgBuf[0])), uintptr(len(cfgBuf)), uintptr(unsafe.Pointer(&need))); r != 0 {
		cfg := (*queryServiceConfigW)(unsafe.Pointer(&cfgBuf[0]))
		s.StartType = name2(startNames, cfg.StartType)
		if cfg.BinaryPathName != nil {
			s.ImagePath = syscall.UTF16ToString((*[32768]uint16)(unsafe.Pointer(cfg.BinaryPathName))[:])
		}
	}
	return s
}

type queryServiceConfigW struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   *uint16
	LoadOrderGroup   *uint16
	TagId            uint32
	Dependencies     *uint16
	ServiceStartName *uint16
	DisplayName      *uint16
}

func name2(m map[uint32]string, k uint32) string {
	if s, ok := m[k]; ok {
		return s
	}
	return fmt.Sprintf("unknown(%d)", k)
}

// --- Registry ---------------------------------------------------------------

func regOpen(root syscall.Handle, path string) (syscall.Handle, error) {
	var h syscall.Handle
	err := syscall.RegOpenKeyEx(root, utf16(path), 0, syscall.KEY_READ|0x0100 /*WOW64_64*/, &h)
	return h, err
}

func regString(path, name string) string {
	h, err := regOpen(syscall.HKEY_LOCAL_MACHINE, path)
	if err != nil {
		return ""
	}
	defer syscall.RegCloseKey(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf) * 2)
	var typ uint32
	if syscall.RegQueryValueEx(h, utf16(name), nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n) != nil {
		return ""
	}
	if typ != syscall.REG_SZ && typ != syscall.REG_EXPAND_SZ {
		return ""
	}
	return syscall.UTF16ToString(buf[:n/2])
}

func regExists(path string) bool {
	h, err := regOpen(syscall.HKEY_LOCAL_MACHINE, path)
	if err != nil {
		return false
	}
	syscall.RegCloseKey(h)
	return true
}

func regValues(path string) map[string]string {
	out := map[string]string{}
	h, err := regOpen(syscall.HKEY_LOCAL_MACHINE, path)
	if err != nil {
		return out
	}
	defer syscall.RegCloseKey(h)
	for i := uint32(0); ; i++ {
		name := make([]uint16, 512)
		nlen := uint32(len(name))
		data := make([]byte, 4096)
		dlen := uint32(len(data))
		var typ uint32
		r, _, _ := procRegEnumValueW.Call(uintptr(h), uintptr(i), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nlen)), 0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&dlen)))
		if r != 0 {
			return out
		}
		key := syscall.UTF16ToString(name[:nlen])
		switch typ {
		case syscall.REG_SZ, syscall.REG_EXPAND_SZ:
			out[key] = syscall.UTF16ToString((*[2048]uint16)(unsafe.Pointer(&data[0]))[: dlen/2 : dlen/2])
		case syscall.REG_DWORD:
			out[key] = fmt.Sprintf("%d", *(*uint32)(unsafe.Pointer(&data[0])))
		default:
			out[key] = fmt.Sprintf("<binary %dB>", dlen)
		}
	}
}
