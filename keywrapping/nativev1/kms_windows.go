//go:build windows

package nativev1

import (
	"crypto/sha256"
	"debug/pe"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// loadPlatformLibrary verifies and loads the Windows native KMS library (see windowspolicy.go).
func loadPlatformLibrary() (kmsLibrary, error) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return nil, untrustedCause(err, "Could not read the Program Files location")
	}
	return winLoad(filepath.Join(programFiles, "HkdfGuard", "v1", winFileName), winExpectedPublisher)
}

func winLoad(path, expectedPublisher string) (kmsLibrary, error) {
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		return nil, notInstalled("The HkdfGuard native KMS library is not installed at '%s'. Install it there; it is never loaded from anywhere else.", path)
	}

	if err := winVerifyLocation(path); err != nil {
		return nil, err
	}
	if err := winVerifySignature(path, expectedPublisher); err != nil {
		return nil, err
	}
	if err := winVerifyImageKindOf(path); err != nil {
		return nil, err
	}
	version, ok := winReadFileVersion(path)
	if err := winRequireMinimumVersion(path, version, ok); err != nil {
		return nil, err
	}
	if err := winVerifyNotRevoked(path); err != nil {
		return nil, err
	}

	// Absolute path, so no probing for the library itself; its own imports (kernel32, advapi32,
	// ncrypt) come from System32 only, never the application directory or PATH.
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, untrustedCause(err, "'%s' passed verification but could not be loaded", path)
	}
	if err := winVerifyModuleIsFile(handle, path); err != nil {
		_ = windows.FreeLibrary(handle)
		return nil, err
	}

	library := &winLibrary{handle: handle}
	for _, export := range []struct {
		name   string
		target *uintptr
	}{
		{"hkdfguard_wrap_dek", &library.wrap},
		{"hkdfguard_unwrap_dek", &library.unwrap},
		{"hkdfguard_generate_and_wrap_dek", &library.generateAndWrap},
		{"hkdfguard_open_file", &library.openFileProc},
		{"hkdfguard_harden_process_with_flags", &library.hardenProc},
	} {
		address, err := windows.GetProcAddress(handle, export.name)
		if err != nil {
			_ = windows.FreeLibrary(handle)
			return nil, untrusted("'%s' has no '%s' export; it is not the HkdfGuard native library.", path, export.name)
		}
		*export.target = address
	}
	return library, nil
}

// winReadFileVersion reads the file version (major, minor, patch) from path's version resource,
// through version.dll from System32; ok is false if the file has none or it can't be read.
func winReadFileVersion(path string) (version [3]uint16, ok bool) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return version, false
	}
	block := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&block[0])); err != nil {
		return version, false
	}
	var info *windows.VS_FIXEDFILEINFO
	var length uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&block[0]), `\`, unsafe.Pointer(&info), &length); err != nil ||
		info == nil || length < uint32(unsafe.Sizeof(*info)) || info.Signature != 0xFEEF04BD {
		return version, false
	}
	version = [3]uint16{uint16(info.FileVersionMS >> 16), uint16(info.FileVersionMS), uint16(info.FileVersionLS >> 16)}
	runtime.KeepAlive(block)
	return version, true
}

// winVerifyModuleIsFile reads the file Windows mapped handle from and requires it to be path (see
// winVerifyLoadedModule).
func winVerifyModuleIsFile(handle windows.Handle, path string) error {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetModuleFileName(handle, &buffer[0], uint32(len(buffer)))
	if err != nil {
		return untrustedCause(err, "Could not read which file Windows loaded for '%s'", path)
	}
	if n == 0 || n >= uint32(len(buffer)) {
		return untrusted("Could not read which file Windows loaded for '%s'.", path)
	}
	return winVerifyLoadedModule(path, windows.UTF16ToString(buffer[:n]))
}

// winVerifyLocation checks the file and each parent folder below the drive root: not a reparse
// point, and owned and writable only by trusted principals. The drive root itself must be owned by
// a trusted principal and let no one else rename or delete what's directly beneath it.
func winVerifyLocation(path string) error {
	item, err := filepath.Abs(path)
	if err != nil {
		return untrustedCause(err, "Could not resolve '%s'", path)
	}

	for {
		parent := filepath.Dir(item)
		security, err := winReadSecurity(item)
		if err != nil {
			return err
		}

		if parent == item {
			return winVerifyTrustedOnly(security, item, winGuardedRootRights, winDescribeSID)
		}

		if err := winVerifyNotReparsePoint(item); err != nil {
			return err
		}
		if err := winVerifyTrustedOnly(security, item, winGuardedRights, winDescribeSID); err != nil {
			return err
		}

		item = parent
	}
}

// winVerifyNotReparsePoint refuses a file or folder that is a symbolic link or junction, either of
// which could redirect a trusted-looking path somewhere writable.
func winVerifyNotReparsePoint(item string) error {
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(item))
	if err != nil {
		return untrustedCause(err, "Could not read the attributes of '%s'", item)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return untrusted("'%s' is a symbolic link or junction; the HkdfGuard native library is only loaded through a real path.", item)
	}
	return nil
}

// winReadSecurity reads an item's owner and DACL into the plain form the policy checks.
func winReadSecurity(path string) (winSecurity, error) {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return winSecurity{}, untrustedCause(err, "Could not read the security descriptor of '%s'", path)
	}

	var security winSecurity
	if owner, _, err := descriptor.Owner(); err == nil && owner != nil {
		security.owner = owner.String()
	}

	dacl, _, err := descriptor.DACL()
	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil):
		security.daclAbsent = true
		return security, nil
	case err != nil:
		return winSecurity{}, untrustedCause(err, "Could not read the DACL of '%s'", path)
	}

	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return winSecurity{}, untrustedCause(err, "Could not read access control entry %d of '%s'", i, path)
		}

		entry := winACE{aceType: ace.Header.AceType, flags: ace.Header.AceFlags, mask: uint32(ace.Mask)}
		switch entry.aceType {
		case aceTypeAccessAllowed, aceTypeAccessDenied, aceTypeAccessAllowedCallback, aceTypeAccessDeniedCallback:
			// These share ACCESS_ALLOWED_ACE's layout up to the SID.
			entry.sid = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		}
		security.aces = append(security.aces, entry)
	}
	return security, nil
}

// winDescribeSID renders a SID as "DOMAIN\account (S-...)", or just the SID if it maps to no
// account here.
func winDescribeSID(sid string) string {
	parsed, err := windows.StringToSid(sid)
	if err != nil {
		return sid
	}
	account, domain, _, err := parsed.LookupAccount("")
	if err != nil {
		return sid
	}
	if domain != "" {
		account = domain + `\` + account
	}
	return account + " (" + sid + ")"
}

// winVerifySignature requires a valid, trusted Authenticode signature whose signer passes
// winVerifySignerIdentity.
func winVerifySignature(path, expectedPublisher string) error {
	subject, ekus, rootSHA256, err := winReadVerifiedSigner(path)
	if err != nil {
		return err
	}
	return winVerifySignerIdentity(path, subject, ekus, rootSHA256, expectedPublisher)
}

var (
	modWintrust                        = windows.NewLazySystemDLL("wintrust.dll")
	procWTHelperProvDataFromStateData  = modWintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain = modWintrust.NewProc("WTHelperGetProvSignerFromChain")

	modCrypt32         = windows.NewLazySystemDLL("crypt32.dll")
	procCertNameToStrW = modCrypt32.NewProc("CertNameToStrW")
)

// cryptProviderSigner is CRYPT_PROVIDER_SGNR; pChainContext is its last member.
type cryptProviderSigner struct {
	size               uint32
	verifyAsOf         windows.Filetime
	certChainCount     uint32
	certChain          uintptr
	signerType         uint32
	signer             uintptr
	errorCode          uint32
	counterSignerCount uint32
	counterSigners     uintptr
	chainContext       *windows.CertChainContext
}

// winVerifyNotRevoked is a second, separate WinVerifyTrust pass, run once every other check has
// passed: the same generic Authenticode policy, now checking revocation across the whole chain
// (except the root) and allowed to fetch revocation data over the network. Only a definite
// revocation refuses the load (see winRevocationDecision); an offline host still starts. Lifetime
// signing is deliberately not requested: Artifact Signing certificates live about three days, and
// it would make every timestamped signature expire with them.
func winVerifyNotRevoked(path string) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return untrustedCause(err, "Invalid path '%s'", path)
	}

	file := windows.WinTrustFileInfo{FilePath: pathPtr}
	file.Size = uint32(unsafe.Sizeof(file))
	data := windows.WinTrustData{
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_WHOLECHAIN,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&file),
		StateAction:                     windows.WTD_STATEACTION_IGNORE,
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
	}
	data.Size = uint32(unsafe.Sizeof(data))

	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	runtime.KeepAlive(&file)
	var status uint32
	var errno syscall.Errno
	if errors.As(verifyErr, &errno) {
		status = uint32(errno)
	}
	return winRevocationDecision(path, status)
}

// signerAt converts the address WTHelperGetProvSignerFromChain returns - memory WinVerifyTrust
// owns until its state is closed, never the Go heap - to a pointer.
func signerAt(address uintptr) *cryptProviderSigner {
	return *(**cryptProviderSigner)(unsafe.Pointer(&address))
}

// winReadVerifiedSigner verifies the signature with WinVerifyTrust (the generic Authenticode
// policy, honouring a timestamp countersignature, without revocation checks or network fetches)
// and reads the signer from the chain WinVerifyTrust itself validated, rather than building a
// second chain that might differ from it.
func winReadVerifiedSigner(path string) (subject string, ekus []string, rootSHA256 string, err error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", nil, "", untrustedCause(err, "Invalid path '%s'", path)
	}

	file := windows.WinTrustFileInfo{FilePath: pathPtr}
	file.Size = uint32(unsafe.Sizeof(file))
	data := windows.WinTrustData{
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&file),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	data.Size = uint32(unsafe.Sizeof(data))

	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	defer func() {
		// Release the state the verify call allocated, whatever it returned. Everything read
		// from the chain below is copied out before this runs.
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
		runtime.KeepAlive(&file)
	}()
	if verifyErr != nil {
		return "", nil, "", untrusted("'%s' does not carry a valid, trusted Authenticode signature (WinVerifyTrust: %v).", path, verifyErr)
	}

	provider, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(data.StateData))
	if provider == 0 {
		return "", nil, "", untrusted("Could not read the Authenticode signer of '%s'; refusing to load it.", path)
	}
	signerAddress, _, _ := procWTHelperGetProvSignerFromChain.Call(provider, 0, 0, 0)
	signer := signerAt(signerAddress)
	if signer == nil || uintptr(signer.size) < unsafe.Sizeof(*signer) || signer.chainContext == nil {
		return "", nil, "", untrusted("Could not read the Authenticode signer of '%s'; refusing to load it.", path)
	}

	// An Authenticode signer's chain is a single simple chain, leaf first and root last; anything
	// else is refused rather than guessed at.
	chain := signer.chainContext
	if chain.ChainCount != 1 || chain.Chains == nil {
		return "", nil, "", untrusted("The Authenticode signer of '%s' has %d certificate chains, not one; refusing to load it.", path, chain.ChainCount)
	}
	simple := *chain.Chains
	if simple == nil || simple.NumElements == 0 || simple.Elements == nil {
		return "", nil, "", untrusted("The Authenticode signer of '%s' has an empty certificate chain; refusing to load it.", path)
	}
	elements := unsafe.Slice(simple.Elements, simple.NumElements)
	leaf, root := elements[0].CertContext, elements[len(elements)-1].CertContext
	if leaf == nil || root == nil || leaf.CertInfo == nil {
		return "", nil, "", untrusted("The Authenticode signer of '%s' has an incomplete certificate chain; refusing to load it.", path)
	}

	subject, err = winCertSubject(leaf)
	if err != nil {
		return "", nil, "", untrustedCause(err, "Could not read the signer subject of '%s'", path)
	}
	ekus, err = winCertEKUs(leaf.CertInfo)
	if err != nil {
		return "", nil, "", untrustedCause(err, "Could not read the signer EKUs of '%s'", path)
	}
	rootHash := sha256.Sum256(unsafe.Slice(root.EncodedCert, root.Length))
	return subject, ekus, strings.ToUpper(hex.EncodeToString(rootHash[:])), nil
}

// CertNameToStr flags: the X.500 form, most significant RDN last reversed to CN first - how
// Windows (and .NET's X509Certificate.Subject) renders a subject.
const (
	x509ASNEncoding        = 0x1
	certX500NameStr        = 3
	certNameStrReverseFlag = 0x02000000
)

func winCertSubject(cert *windows.CertContext) (string, error) {
	name := &cert.CertInfo.Subject
	flags := uintptr(certX500NameStr | certNameStrReverseFlag)
	size, _, _ := procCertNameToStrW.Call(x509ASNEncoding, uintptr(unsafe.Pointer(name)), flags, 0, 0)
	if size == 0 {
		return "", errors.New("CertNameToStrW returned no name")
	}
	buffer := make([]uint16, size)
	procCertNameToStrW.Call(x509ASNEncoding, uintptr(unsafe.Pointer(name)), flags, uintptr(unsafe.Pointer(&buffer[0])), size)
	return windows.UTF16ToString(buffer), nil
}

// winCertEKUs returns the certificate's extended key usage OIDs, or none if it has no EKU
// extension.
func winCertEKUs(info *windows.CertInfo) ([]string, error) {
	if info.CountExtensions == 0 || info.Extensions == nil {
		return nil, nil
	}
	for _, extension := range unsafe.Slice(info.Extensions, info.CountExtensions) {
		if windows.BytePtrToString(extension.ObjId) != "2.5.29.37" {
			continue
		}
		var oids []asn1.ObjectIdentifier
		value := unsafe.Slice(extension.Value.Data, extension.Value.Size)
		if rest, err := asn1.Unmarshal(value, &oids); err != nil || len(rest) != 0 {
			return nil, errors.New("malformed extended key usage extension")
		}
		ekus := make([]string, len(oids))
		for i, oid := range oids {
			ekus[i] = oid.String()
		}
		return ekus, nil
	}
	return nil, nil
}

// winVerifyImageKindOf reads the PE header and applies winVerifyImageKind.
func winVerifyImageKindOf(path string) error {
	file, err := pe.Open(path)
	if err != nil {
		return untrustedCause(err, "Could not read the PE header of '%s'; refusing to load it", path)
	}
	defer file.Close()
	return winVerifyImageKind(path, file.FileHeader.Characteristics, file.FileHeader.Machine, runtime.GOARCH)
}

// winLibrary is the loaded HkdfGuard.dll and its exports.
type winLibrary struct {
	handle                        windows.Handle
	wrap, unwrap, generateAndWrap uintptr
	openFileProc                  uintptr
	hardenProc                    uintptr
}

func (l *winLibrary) wrapDEK(service string, dek, out []byte) (int32, int32) {
	return winCall(l.wrap, service, dek, out)
}

func (l *winLibrary) unwrapDEK(service string, wrapped, out []byte) (int32, int32) {
	return winCall(l.unwrap, service, wrapped, out)
}

func winCall(proc uintptr, service string, in, out []byte) (int32, int32) {
	cservice, err := windows.BytePtrFromString(service)
	if err != nil {
		return errInvalidArgument, 0
	}
	outLen := int32(len(out))
	status, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(cservice)),
		uintptr(unsafe.Pointer(unsafe.SliceData(in))), uintptr(len(in)),
		uintptr(unsafe.Pointer(unsafe.SliceData(out))), uintptr(unsafe.Pointer(&outLen)))
	runtime.KeepAlive(in)
	runtime.KeepAlive(out)
	return int32(status), outLen
}

func (l *winLibrary) generateAndWrapDEK(service string, out []byte) (int32, int32) {
	cservice, err := windows.BytePtrFromString(service)
	if err != nil {
		return errInvalidArgument, 0
	}
	outLen := int32(len(out))
	status, _, _ := syscall.SyscallN(l.generateAndWrap,
		uintptr(unsafe.Pointer(cservice)),
		uintptr(unsafe.Pointer(unsafe.SliceData(out))), uintptr(unsafe.Pointer(&outLen)))
	runtime.KeepAlive(out)
	return int32(status), outLen
}

// openFile is hkdfguard_open_file(const char* path, uint8_t* out, int* out_len).
func (l *winLibrary) openFile(path string, out []byte) (int32, int32, error) {
	cpath, err := windows.BytePtrFromString(path)
	if err != nil {
		return errInvalidArgument, 0, nil
	}
	outLen := int32(len(out))
	status, _, _ := syscall.SyscallN(l.openFileProc,
		uintptr(unsafe.Pointer(cpath)),
		uintptr(unsafe.Pointer(unsafe.SliceData(out))), uintptr(unsafe.Pointer(&outLen)))
	runtime.KeepAlive(cpath)
	runtime.KeepAlive(out)
	return int32(status), outLen, nil
}

func (l *winLibrary) describeStatus(status int32) string { return describeWindowsStatus(status) }

// hardenProcess is hkdfguard_harden_process_with_flags(unsigned int flags).
func (l *winLibrary) hardenProcess(flags uint32) int32 {
	status, _, _ := syscall.SyscallN(l.hardenProc, uintptr(flags))
	return int32(status)
}
