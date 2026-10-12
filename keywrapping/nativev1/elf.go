package nativev1

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
)

// Reads the DT_NEEDED entries - the shared libraries an ELF object asks the dynamic linker to load
// - from a 64-bit little-endian ELF file (amd64 and arm64 Linux). Only the ELF header, the program
// headers, the dynamic segment and its string table are read, each bounded. Anything malformed is
// refused: the caller is deciding whether to trust what the file pulled into the process. (Go's
// debug/elf is not hardened against adversarial input, so it isn't used here.)

const (
	elfHeaderSize        = 64
	elfProgramHeaderSize = 56
	elfDynamicEntrySize  = 16
	elfMaxProgramHeaders = 4096
	elfMaxSegmentBytes   = 1 << 20

	elfPTLoad    = 1
	elfPTDynamic = 2

	elfDTNull   = 0
	elfDTNeeded = 1
	elfDTStrTab = 5
	elfDTStrSz  = 10
)

// elfReadNeededFile returns the DT_NEEDED names of the ELF file at path, in file order.
func elfReadNeededFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return elfReadNeeded(path, func(offset int64, count int) ([]byte, bool) {
		buffer := make([]byte, count)
		// ReadAt may report io.EOF alongside a complete read at the end of the file; only a short
		// read counts as running past the end.
		n, _ := file.ReadAt(buffer, offset)
		return buffer, n == count
	})
}

// elfReadNeeded parses DT_NEEDED names through read, which returns exactly count bytes at offset,
// or false if the file is shorter. path names the file in errors.
func elfReadNeeded(path string, read func(offset int64, count int) ([]byte, bool)) ([]string, error) {
	header, err := elfRead(path, read, 0, elfHeaderSize, "ELF header")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(header[:4], []byte{0x7F, 'E', 'L', 'F'}) {
		return nil, elfMalformed(path, "it is not an ELF file")
	}
	if header[4] != 2 || header[5] != 1 {
		return nil, elfMalformed(path, "it is not a 64-bit little-endian ELF file")
	}

	le := binary.LittleEndian
	programHeaderOffset, err := elfOffset(path, le.Uint64(header[32:]))
	if err != nil {
		return nil, err
	}
	programHeaderSize := int(le.Uint16(header[54:]))
	programHeaderCount := int(le.Uint16(header[56:]))
	if programHeaderSize < elfProgramHeaderSize || programHeaderCount == 0 || programHeaderCount > elfMaxProgramHeaders {
		return nil, elfMalformed(path, "its program header table is malformed")
	}

	programHeaders, err := elfRead(path, read, programHeaderOffset, programHeaderSize*programHeaderCount, "program headers")
	if err != nil {
		return nil, err
	}

	type load struct {
		virtualAddress, fileSize uint64
		offset                   int64
	}
	var loads []load
	var dynamicOffset int64
	dynamicSize := -1
	for i := range programHeaderCount {
		entry := programHeaders[i*programHeaderSize : (i+1)*programHeaderSize]
		offset, err := elfOffset(path, le.Uint64(entry[8:]))
		if err != nil {
			return nil, err
		}
		virtualAddress := le.Uint64(entry[16:])
		fileSize := le.Uint64(entry[32:])

		switch le.Uint32(entry) {
		case elfPTLoad:
			loads = append(loads, load{virtualAddress, fileSize, offset})
		case elfPTDynamic:
			size, err := elfSize(path, fileSize, "dynamic segment")
			if err != nil {
				return nil, err
			}
			dynamicOffset, dynamicSize = offset, size
		}
	}

	if dynamicSize < 0 {
		return []string{}, nil
	}

	entries, err := elfRead(path, read, dynamicOffset, dynamicSize-dynamicSize%elfDynamicEntrySize, "dynamic segment")
	if err != nil {
		return nil, err
	}

	var neededOffsets []uint64
	var stringTableAddress, stringTableSize uint64
	var haveAddress, haveSize bool
	for at := 0; at+elfDynamicEntrySize <= len(entries); at += elfDynamicEntrySize {
		tag := int64(le.Uint64(entries[at:]))
		value := le.Uint64(entries[at+8:])
		if tag == elfDTNull {
			break
		}
		switch tag {
		case elfDTNeeded:
			neededOffsets = append(neededOffsets, value)
		case elfDTStrTab:
			stringTableAddress, haveAddress = value, true
		case elfDTStrSz:
			stringTableSize, haveSize = value, true
		}
	}

	if len(neededOffsets) == 0 {
		return []string{}, nil
	}
	if !haveAddress || !haveSize {
		return nil, elfMalformed(path, "it names dependencies but has no string table")
	}

	// DT_STRTAB is a virtual address; the PT_LOAD segment containing it maps it to the file.
	containing := -1
	for i, l := range loads {
		if stringTableAddress >= l.virtualAddress && stringTableAddress-l.virtualAddress < l.fileSize {
			containing = i
			break
		}
	}
	if containing < 0 {
		return nil, elfMalformed(path, "its string table lies outside every loaded segment")
	}

	delta := stringTableAddress - loads[containing].virtualAddress
	if delta > math.MaxInt64-uint64(loads[containing].offset) {
		return nil, elfMalformed(path, "a file offset is out of range")
	}
	size, err := elfSize(path, stringTableSize, "string table")
	if err != nil {
		return nil, err
	}
	table, err := elfRead(path, read, loads[containing].offset+int64(delta), size, "string table")
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(neededOffsets))
	for _, offset := range neededOffsets {
		end := -1
		if offset < uint64(len(table)) {
			end = bytes.IndexByte(table[offset:], 0)
		}
		if end < 0 {
			return nil, elfMalformed(path, "a dependency name runs past its string table")
		}
		names = append(names, string(table[offset:offset+uint64(end)]))
	}
	return names, nil
}

func elfRead(path string, read func(int64, int) ([]byte, bool), offset int64, count int, what string) ([]byte, error) {
	if b, ok := read(offset, count); ok && len(b) == count {
		return b, nil
	}
	return nil, elfMalformed(path, "its "+what+" runs past the end of the file")
}

func elfOffset(path string, value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, elfMalformed(path, "a file offset is out of range")
	}
	return int64(value), nil
}

func elfSize(path string, value uint64, what string) (int, error) {
	if value > elfMaxSegmentBytes {
		return 0, elfMalformed(path, "its "+what+" is implausibly large")
	}
	return int(value), nil
}

func elfMalformed(path, reason string) error {
	return untrusted("'%s' is not a well-formed ELF shared object: %s.", path, reason)
}
