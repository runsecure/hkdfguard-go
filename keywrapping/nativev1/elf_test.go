package nativev1

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const elfLoadAddress = 0x40_0000

type elfOptions struct {
	withoutDynamic            bool
	withoutStringTable        bool
	withoutStringTableSize    bool
	stringTableAddress        *uint64
	neededOffset              *uint64
	stringTableSizeAdjustment int
}

// syntheticELF builds a minimal 64-bit little-endian ELF image: one PT_LOAD mapping the whole file
// at elfLoadAddress, one PT_DYNAMIC, and a string table holding the given names.
func syntheticELF(needed []string, o elfOptions) []byte {
	const header, phdrs = 64, 2 * 56
	strs := []byte{0}
	var offsets []uint64
	for _, name := range needed {
		offset := uint64(len(strs))
		if o.neededOffset != nil {
			offset = *o.neededOffset
		}
		offsets = append(offsets, offset)
		strs = append(append(strs, name...), 0)
	}

	type dyn struct {
		tag   int64
		value uint64
	}
	var dynamic []dyn
	for _, offset := range offsets {
		dynamic = append(dynamic, dyn{1, offset})
	}
	stringTableOffset := header + phdrs + (len(needed)+3)*16
	if !o.withoutStringTable {
		address := uint64(elfLoadAddress + stringTableOffset)
		if o.stringTableAddress != nil {
			address = *o.stringTableAddress
		}
		dynamic = append(dynamic, dyn{5, address})
		if !o.withoutStringTableSize {
			dynamic = append(dynamic, dyn{10, uint64(len(strs) + o.stringTableSizeAdjustment)})
		}
	}
	dynamic = append(dynamic, dyn{0, 0})

	le := binary.LittleEndian
	image := make([]byte, stringTableOffset+len(strs))
	copy(image, []byte{0x7F, 'E', 'L', 'F', 2, 1, 1})
	le.PutUint64(image[32:], header) // e_phoff
	le.PutUint16(image[54:], 56)     // e_phentsize
	le.PutUint16(image[56:], 2)      // e_phnum

	programHeader := func(index int, typ uint32, offset, address, size uint64) {
		at := header + index*56
		le.PutUint32(image[at:], typ)
		le.PutUint64(image[at+8:], offset)
		le.PutUint64(image[at+16:], address)
		le.PutUint64(image[at+32:], size)
	}
	dynamicOffset := header + phdrs
	programHeader(0, 1, 0, elfLoadAddress, uint64(len(image)))
	dynamicType := uint32(2)
	if o.withoutDynamic {
		dynamicType = 4
	}
	programHeader(1, dynamicType, uint64(dynamicOffset), uint64(elfLoadAddress+dynamicOffset), uint64(len(dynamic)*16))
	for i, d := range dynamic {
		le.PutUint64(image[dynamicOffset+i*16:], uint64(d.tag))
		le.PutUint64(image[dynamicOffset+i*16+8:], d.value)
	}

	copy(image[stringTableOffset:], strs)
	return image
}

func parseELF(image []byte) ([]string, error) {
	return elfReadNeeded("test.so", func(offset int64, count int) ([]byte, bool) {
		if offset < 0 || offset+int64(count) > int64(len(image)) {
			return nil, false
		}
		return slices.Clone(image[offset : offset+int64(count)]), true
	})
}

func ptr(v uint64) *uint64 { return &v }

func TestELF_ReadsEveryNeededNameInOrder(t *testing.T) {
	names, err := parseELF(syntheticELF([]string{"libtss2-esys.so.0", "libc.so.6"}, elfOptions{}))

	if err != nil || !slices.Equal(names, []string{"libtss2-esys.so.0", "libc.so.6"}) {
		t.Errorf("got %v, %v", names, err)
	}
}

func TestELF_AnObjectWithNoDependencies_HasNone(t *testing.T) {
	images := [][]byte{
		syntheticELF(nil, elfOptions{}),
		syntheticELF(nil, elfOptions{withoutStringTable: true}),
		syntheticELF([]string{"ignored.so"}, elfOptions{withoutDynamic: true}),
	}
	for i, image := range images {
		if names, err := parseELF(image); err != nil || len(names) != 0 {
			t.Errorf("image %d: got %v, %v", i, names, err)
		}
	}
}

func TestELF_AMalformedImage_IsRefused(t *testing.T) {
	base := func() []byte { return syntheticELF([]string{"x.so"}, elfOptions{}) }
	le := binary.LittleEndian

	notELF := base()
	notELF[1] = 'X'
	elf32 := base()
	elf32[4] = 1
	bigEndian := base()
	bigEndian[5] = 2
	noProgramHeaders := base()
	le.PutUint16(noProgramHeaders[56:], 0)
	hugeOffset := base()
	le.PutUint64(hugeOffset[32:], ^uint64(0))
	hugeDynamic := base()
	le.PutUint64(hugeDynamic[64+56+32:], 2<<20)
	hugeProgramHeaderTable := base() // 65535-byte entries x 4096 entries: 256 MB before any read
	le.PutUint16(hugeProgramHeaderTable[54:], 0xFFFF)
	le.PutUint16(hugeProgramHeaderTable[56:], elfMaxProgramHeaders)

	cases := []struct {
		reason string
		image  []byte
	}{
		{"not an ELF file", notELF},
		{"not a 64-bit little-endian", elf32},
		{"not a 64-bit little-endian", bigEndian},
		{"program header table is malformed", noProgramHeaders},
		{"out of range", hugeOffset},
		{"implausibly large", hugeDynamic},
		{"implausibly large", hugeProgramHeaderTable},
		{"runs past the end", base()[:40]},
		{"runs past the end", base()[:len(base())-3]},
		{"no string table", syntheticELF([]string{"x.so"}, elfOptions{withoutStringTable: true})},
		{"no string table", syntheticELF([]string{"x.so"}, elfOptions{withoutStringTableSize: true})}, // DT_STRTAB without DT_STRSZ
		{"outside every loaded segment", syntheticELF([]string{"x.so"}, elfOptions{stringTableAddress: ptr(0x10)})},
		{"runs past its string table", syntheticELF([]string{"x.so"}, elfOptions{neededOffset: ptr(4096)})},
		{"runs past its string table", syntheticELF([]string{"x.so"}, elfOptions{stringTableSizeAdjustment: -1})}, // no terminating NUL
	}
	for _, c := range cases {
		_, err := parseELF(c.image)
		requireUntrusted(t, err, "test.so", c.reason)
	}
}

func TestELF_ReadsFromAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lib.so")

	if err := os.WriteFile(path, syntheticELF([]string{"libc.so.6"}, elfOptions{}), 0o644); err != nil {
		t.Fatal(err)
	}
	if names, err := elfReadNeededFile(path); err != nil || !slices.Equal(names, []string{"libc.so.6"}) {
		t.Errorf("got %v, %v", names, err)
	}

	if err := os.WriteFile(path, syntheticELF([]string{"libc.so.6"}, elfOptions{})[:100], 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := elfReadNeededFile(path)
	requireUntrusted(t, err)
}
