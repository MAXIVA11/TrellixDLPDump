package main

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

// Authenticode verification, so FTDLP can state whether each DLP binary is the
// genuine vendor-signed file rather than trusting the path. Read-only.

var (
	wintrust = syscall.NewLazyDLL("wintrust.dll")
	crypt32  = syscall.NewLazyDLL("crypt32.dll")

	procWinVerifyTrust   = wintrust.NewProc("WinVerifyTrust")
	procCryptQueryObject = crypt32.NewProc("CryptQueryObject")
	procCryptMsgGetParam = crypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = crypt32.NewProc("CryptMsgClose")
	procCertFindCert     = crypt32.NewProc("CertFindCertificateInStore")
	procCertGetName      = crypt32.NewProc("CertGetNameStringW")
	procCertFreeCtx      = crypt32.NewProc("CertFreeCertificateContext")
	procCertCloseStore   = crypt32.NewProc("CertCloseStore")
)

var winTrustActionGenericVerifyV2 = syscall.GUID{
	Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11d0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

type wintrustFileInfo struct {
	cbStruct     uint32
	filePath     *uint16
	hFile        syscall.Handle
	knownSubject *syscall.GUID
}

type wintrustData struct {
	cbStruct           uint32
	policyCallbackData uintptr
	sipClientData      uintptr
	uiChoice           uint32
	revocationChecks   uint32
	unionChoice        uint32
	fileInfo           *wintrustFileInfo
	stateAction        uint32
	hWVTStateData      syscall.Handle
	urlReference       *uint16
	provFlags          uint32
	uiContext          uint32
	signatureSettings  uintptr
}

// Signature is FTDLP's verdict for one file.
type Signature struct {
	Trust  string `json:"trust"`            // trusted | untrusted | unsigned | error
	Signer string `json:"signer,omitempty"` // common name from the signing cert
	Detail string `json:"detail,omitempty"`
}

const (
	wtdUINone              = 2
	wtdRevokeNone          = 0
	wtdChoiceFile          = 1
	wtdStateActionVerify   = 1
	wtdStateActionClose    = 2
	wtdRevocationCheckNone = 0x00000010
	wtdCacheOnlyURL        = 0x00001000
	trustENoSignature      = 0x800B0100
	trustEBadDigest        = 0x80096010
	trustESubjectForm      = 0x800B0003
	trustEProviderUnknown  = 0x800B0001
)

func verifySignature(path string) Signature {
	p := utf16(path)
	fi := wintrustFileInfo{filePath: p}
	fi.cbStruct = uint32(unsafe.Sizeof(fi))
	d := wintrustData{
		uiChoice:         wtdUINone,
		revocationChecks: wtdRevokeNone,
		unionChoice:      wtdChoiceFile,
		fileInfo:         &fi,
		stateAction:      wtdStateActionVerify,
		provFlags:        wtdRevocationCheckNone | wtdCacheOnlyURL,
	}
	d.cbStruct = uint32(unsafe.Sizeof(d))
	invalid := ^uintptr(0)
	r, _, _ := procWinVerifyTrust.Call(invalid, uintptr(unsafe.Pointer(&winTrustActionGenericVerifyV2)), uintptr(unsafe.Pointer(&d)))
	d.stateAction = wtdStateActionClose
	procWinVerifyTrust.Call(invalid, uintptr(unsafe.Pointer(&winTrustActionGenericVerifyV2)), uintptr(unsafe.Pointer(&d)))

	sig := Signature{Signer: signerName(path)}
	switch uint32(r) {
	case 0:
		sig.Trust = "trusted"
	case trustENoSignature, trustESubjectForm, trustEProviderUnknown:
		sig.Trust = "unsigned"
	case trustEBadDigest:
		sig.Trust, sig.Detail = "untrusted", "contents do not match the signature (tampered)"
	default:
		sig.Trust, sig.Detail = "untrusted", fmt.Sprintf("0x%08X", uint32(r))
	}
	return sig
}

const (
	certQueryObjectFile       = 1
	certContentFlagPKCS7Embed = 0x00000400
	certFormatFlagBinary      = 2
	cmsgSignerCertInfoParam   = 7
	certFindSubjectCert       = 0x00070000
	certNameSimpleDisplayType = 4
	x509AsnEncoding           = 1
	pkcs7AsnEncoding          = 0x10000
)

// signerName returns the common name on the signing certificate, or "".
func signerName(path string) string {
	var hStore, hMsg uintptr
	r, _, _ := procCryptQueryObject.Call(
		certQueryObjectFile, uintptr(unsafe.Pointer(utf16(path))),
		certContentFlagPKCS7Embed, certFormatFlagBinary, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&hStore)), uintptr(unsafe.Pointer(&hMsg)), 0)
	if r == 0 {
		return ""
	}
	defer procCertCloseStore.Call(hStore, 0)
	defer procCryptMsgClose.Call(hMsg)

	var need uint32
	procCryptMsgGetParam.Call(hMsg, cmsgSignerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&need)))
	if need == 0 {
		return ""
	}
	info := make([]byte, need)
	if r, _, _ := procCryptMsgGetParam.Call(hMsg, cmsgSignerCertInfoParam, 0, uintptr(unsafe.Pointer(&info[0])), uintptr(unsafe.Pointer(&need))); r == 0 {
		return ""
	}
	cert, _, _ := procCertFindCert.Call(hStore, x509AsnEncoding|pkcs7AsnEncoding, 0, certFindSubjectCert, uintptr(unsafe.Pointer(&info[0])), 0)
	if cert == 0 {
		return ""
	}
	defer procCertFreeCtx.Call(cert)
	n, _, _ := procCertGetName.Call(cert, certNameSimpleDisplayType, 0, 0, 0, 0)
	if n <= 1 {
		return ""
	}
	buf := make([]uint16, n)
	procCertGetName.Call(cert, certNameSimpleDisplayType, 0, 0, uintptr(unsafe.Pointer(&buf[0])), n)
	return syscall.UTF16ToString(buf)
}

func baseNoExt(path string) string {
	b := filepath.Base(path)
	return b[:len(b)-len(filepath.Ext(b))]
}
