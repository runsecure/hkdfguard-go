package nativev1

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
)

// Mach-O images built in memory for the version check, which runs on every platform.

func idDylib(version uint32) []byte {
	cmd := make([]byte, 32) // cmd, cmdsize, name offset, timestamp, current, compatibility, "x\0" + padding
	binary.LittleEndian.PutUint32(cmd[0:], machoLCIDDylib)
	binary.LittleEndian.PutUint32(cmd[4:], 32)
	binary.LittleEndian.PutUint32(cmd[8:], 24)
	binary.LittleEndian.PutUint32(cmd[16:], version)
	binary.LittleEndian.PutUint32(cmd[20:], 0x00010000)
	cmd[24] = 'x'
	return cmd
}

func otherCommand() []byte { // LC_UUID
	cmd := make([]byte, 24)
	binary.LittleEndian.PutUint32(cmd[0:], 0x1b)
	binary.LittleEndian.PutUint32(cmd[4:], 24)
	return cmd
}

func thinImage(cputype uint32, commands ...[]byte) []byte {
	var body []byte
	for _, c := range commands {
		body = append(body, c...)
	}
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[0:], machoMagic64)
	binary.LittleEndian.PutUint32(header[4:], cputype)
	binary.LittleEndian.PutUint32(header[12:], 6) // MH_DYLIB
	binary.LittleEndian.PutUint32(header[16:], uint32(len(commands)))
	binary.LittleEndian.PutUint32(header[20:], uint32(len(body)))
	return append(header, body...)
}

// fatImage places each slice at a 4 KiB boundary after a 32-bit fat header.
func fatImage(slices map[uint32][]byte, order ...uint32) []byte {
	out := make([]byte, 8+20*len(order))
	binary.BigEndian.PutUint32(out[0:], machoFatMagic)
	binary.BigEndian.PutUint32(out[4:], uint32(len(order)))
	for i, cpu := range order {
		entry := out[8+20*i:]
		binary.BigEndian.PutUint32(entry[0:], cpu)
		binary.BigEndian.PutUint32(entry[8:], uint32(4096*(i+1)))
		binary.BigEndian.PutUint32(entry[12:], uint32(len(slices[cpu])))
	}
	for i, cpu := range order {
		for len(out) < 4096*(i+1) {
			out = append(out, 0)
		}
		out = append(out, slices[cpu]...)
	}
	return out
}

const cpuX8664 uint32 = 0x01000007

// version packs major.minor.patch the way Mach-O does.
func version(major, minor, patch uint32) uint32 { return major<<16 | minor<<8 | patch }

func TestMacDylibCurrentVersion_ReadsLCIDDylib_FromAThinArm64Image(t *testing.T) {
	got, err := macDylibCurrentVersion(thinImage(machoCPUARM64, otherCommand(), idDylib(version(0, 9, 0))))
	if err != nil || got != version(0, 9, 0) {
		t.Fatalf("got %#x, %v", got, err)
	}
}

func TestMacRequireMinimumVersion_AcceptsTheMinimumAndAbove_RefusesBelow(t *testing.T) {
	if macMinimumLibraryVersion != version(0, 9, 0) {
		t.Fatalf("minimum is %s, want 0.9.0", macFormatVersion(macMinimumLibraryVersion))
	}
	for _, v := range []uint32{version(0, 9, 0), version(0, 9, 1), version(0, 10, 0), version(1, 0, 0)} {
		if err := macRequireMinimumVersion("/lib.dylib", thinImage(machoCPUARM64, idDylib(v))); err != nil {
			t.Errorf("%s: %v", macFormatVersion(v), err)
		}
	}
	err := macRequireMinimumVersion("/lib.dylib", thinImage(machoCPUARM64, idDylib(version(0, 8, 0))))
	requireUntrusted(t, err, "0.8.0", "0.9.0", "/lib.dylib")
}

func TestMacDylibCurrentVersion_RefusesWhatIsNotAWellFormedArm64Dylib(t *testing.T) {
	good := thinImage(machoCPUARM64, otherCommand(), idDylib(version(0, 9, 0)))
	overflow := thinImage(machoCPUARM64, otherCommand(), idDylib(version(0, 9, 0)))
	binary.LittleEndian.PutUint32(overflow[32+4:], 0xfffffff8) // first command's size runs far past the end
	unaligned := thinImage(machoCPUARM64, otherCommand(), idDylib(version(0, 9, 0)))
	binary.LittleEndian.PutUint32(unaligned[32+4:], 20)
	tiny := thinImage(machoCPUARM64, otherCommand(), idDylib(version(0, 9, 0)))
	binary.LittleEndian.PutUint32(tiny[32+4:], 4)
	tooManyCommands := thinImage(machoCPUARM64, otherCommand())
	binary.LittleEndian.PutUint32(tooManyCommands[16:], 5) // ncmds beyond sizeofcmds
	pastRead := thinImage(machoCPUARM64, idDylib(version(0, 9, 0)))
	binary.LittleEndian.PutUint32(pastRead[20:], 1<<20) // sizeofcmds beyond the bytes read
	wrongMagic := append([]byte{}, good...)
	binary.LittleEndian.PutUint32(wrongMagic, 0xfeedface) // 32-bit Mach-O

	cases := map[string][]byte{
		"empty":                    nil,
		"truncated header":         good[:20],
		"truncated load commands":  good[:len(good)-8],
		"cmdsize overflow":         overflow,
		"cmdsize not 8-aligned":    unaligned,
		"cmdsize below 8":          tiny,
		"ncmds beyond sizeofcmds":  tooManyCommands,
		"sizeofcmds past the read": pastRead,
		"wrong magic":              wrongMagic,
		"no LC_ID_DYLIB":           thinImage(machoCPUARM64, otherCommand()),
		"x86_64-only thin file":    thinImage(cpuX8664, idDylib(version(0, 9, 0))),
		"fat without arm64":        fatImage(map[uint32][]byte{cpuX8664: thinImage(cpuX8664, idDylib(version(0, 9, 0)))}, cpuX8664),
	}
	for name, data := range cases {
		if v, err := macDylibCurrentVersion(data); err == nil {
			t.Errorf("%s: accepted, version %#x", name, v)
		}
		requireUntrusted(t, macRequireMinimumVersion("/lib.dylib", data), "/lib.dylib")
	}
}

func TestMacDylibCurrentVersion_ReadsTheArm64SliceOfAFatImage(t *testing.T) {
	data := fatImage(map[uint32][]byte{
		cpuX8664:      thinImage(cpuX8664, idDylib(version(1, 0, 0))),
		machoCPUARM64: thinImage(machoCPUARM64, idDylib(version(0, 10, 0))),
	}, cpuX8664, machoCPUARM64)
	got, err := macDylibCurrentVersion(data)
	if err != nil || got != version(0, 10, 0) {
		t.Fatalf("got %#x, %v", got, err)
	}

	// An arm64 slice that starts beyond what was read is refused, not guessed at.
	if _, err := macDylibCurrentVersion(data[:4096+16]); err == nil {
		t.Error("a truncated arm64 slice was accepted")
	}
	if _, err := macDylibCurrentVersion(data[:4096]); err == nil {
		t.Error("an arm64 slice beyond the bytes read was accepted")
	}
}

func TestMacHomeFromAccount_OnlyAnAbsoluteHomeFromASuccessfulLookup(t *testing.T) {
	cases := []struct {
		home string
		ok   bool
		want string
	}{
		{"/Users/dev", true, "/Users/dev"},
		{"/Users/dev", false, ""},
		{"", true, ""},
		{"Users/dev", true, ""},
		{"~/dev", true, ""},
	}
	for _, c := range cases {
		if got := macHomeFromAccount(c.home, c.ok); got != c.want {
			t.Errorf("(%q, %v) = %q, want %q", c.home, c.ok, got, c.want)
		}
	}
}

func TestMacChoosePath_WithNoUsableHome_ConsidersOnlyTheSystemInstall(t *testing.T) {
	probed := []string{}
	probe := func(path string) int { probed = append(probed, path); return errnoENOENT }
	_, _, err := macChoosePath(probe, macHomeFromAccount("", false))
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("error = %v, want ErrNotInstalled", err)
	}
	for _, p := range probed {
		if p != macSystemPath {
			t.Errorf("probed %q; only the system install should be considered", p)
		}
	}
}

// The release actually installed on this machine, when there is one, passes the check.
func TestMacRequireMinimumVersion_AcceptsTheInstalledRelease(t *testing.T) {
	file, err := os.Open(macSystemPath)
	if err != nil {
		t.Skipf("no system install at %s", macSystemPath)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, macVersionReadLimit))
	if err != nil {
		t.Fatal(err)
	}
	installed, err := macDylibCurrentVersion(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := macRequireMinimumVersion(macSystemPath, data); err != nil {
		t.Fatal(err)
	}
	t.Logf("installed library version %s", macFormatVersion(installed))
}
