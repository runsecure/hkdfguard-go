package nativev1

// What lstat/statx report about one path, shared by the macOS and Linux loader policies. Plain
// data, so the policies can be checked against simulated filesystems on any platform.

type fileType int

const (
	fileOther fileType = iota
	fileRegular
	fileDirectory
	fileSymlink
)

// Permission bits the policies care about.
const (
	permGroupWrite = 0o020
	permOtherWrite = 0o002
)

// errno values the policies distinguish; identical on Linux and macOS.
const (
	errnoENOENT  = 2
	errnoENOTDIR = 20
)

// S_IFMT and its file types; identical on Linux and macOS.
const (
	modeTypeMask  = 0o170000
	modeRegular   = 0o100000
	modeDirectory = 0o040000
	modeSymlink   = 0o120000
	modePermMask  = 0o7777
)

// fileStatus describes one path itself - never what a symbolic link points to.
type fileStatus struct {
	uid  uint32
	gid  uint32
	perm uint32 // the low 12 mode bits
	typ  fileType
}

// statusFromMode builds a fileStatus from a raw st_mode.
func statusFromMode(uid, gid, mode uint32) fileStatus {
	typ := fileOther
	switch mode & modeTypeMask {
	case modeRegular:
		typ = fileRegular
	case modeDirectory:
		typ = fileDirectory
	case modeSymlink:
		typ = fileSymlink
	}
	return fileStatus{uid: uid, gid: gid, perm: mode & modePermMask, typ: typ}
}

func (t fileType) String() string {
	switch t {
	case fileSymlink:
		return "symbolic link"
	case fileDirectory:
		return "directory"
	case fileRegular:
		return "regular file"
	default:
		return "special file"
	}
}
