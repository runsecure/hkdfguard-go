package nativev1

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
)

// Reads the DT_NEEDED entries - the shared libraries an ELF object asks the dynamic linker to load
// - and the PT_INTERP path - the dynamic linker an executable names - from a 64-bit little-endian
// ELF file (amd64 and arm64 Linux). Only the ELF header, the program headers, the interpreter path,
// the dynamic segment and its string table are read, each bounded. Anything malformed is
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
	elfPTInterp  = 3

	// elfMaxInterpreterBytes bounds PT_INTERP, a path: PATH_MAX.
	elfMaxInterpreterBytes = 4096

	elfDTNull   = 0
	elfDTNeeded = 1
	elfDTStrTab = 5
	elfDTStrSz  = 10
)

// elfReadNeededFile returns the DT_NEEDED names of the ELF file at path, in file order.
func elfReadNeededFile(path string) ([]string, error) {
	file, read, err := elfOpenReader(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return elfReadNeeded(path, read)
}

// elfOpenReader opens path for the readers below: read returns exactly count bytes at offset, or
// false if the file is shorter.
func elfOpenReader(path string) (*os.File, func(offset int64, count int) ([]byte, bool), error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return file, func(offset int64, count int) ([]byte, bool) {
		buffer := make([]byte, count)
		// ReadAt may report io.EOF alongside a complete read at the end of the file; only a short
		// read counts as running past the end.
		n, _ := file.ReadAt(buffer, offset)
		return buffer, n == count
	}, nil
}

// elfReadInterpreterFile returns the PT_INTERP path of the ELF file at path - for an executable,
// the dynamic linker the kernel started it with - or "" if it has none.
func elfReadInterpreterFile(path string) (string, error) {
	file, read, err := elfOpenReader(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return elfReadInterpreter(path, read)
}

// elfReadInterpreter parses the PT_INTERP path through read (see elfOpenReader); "" if there is
// none. path names the file in errors.
func elfReadInterpreter(path string, read func(offset int64, count int) ([]byte, bool)) (string, error) {
	programHeaders, programHeaderSize, programHeaderCount, err := elfReadProgramHeaders(path, read)
	if err != nil {
		return "", err
	}
	le := binary.LittleEndian
	for i := range programHeaderCount {
		entry := programHeaders[i*programHeaderSize : (i+1)*programHeaderSize]
		if le.Uint32(entry) != elfPTInterp {
			continue
		}
		offset, err := elfOffset(path, le.Uint64(entry[8:]))
		if err != nil {
			return "", err
		}
		fileSize := le.Uint64(entry[32:])
		if fileSize == 0 || fileSize > elfMaxInterpreterBytes {
			return "", elfMalformed(path, "its interpreter path is empty or implausibly long")
		}
		raw, err := elfRead(path, read, offset, int(fileSize), "interpreter path")
		if err != nil {
			return "", err
		}
		end := bytes.IndexByte(raw, 0)
		if end <= 0 {
			return "", elfMalformed(path, "its interpreter path is not a NUL-terminated string")
		}
		return string(raw[:end]), nil
	}
	return "", nil
}

// elfReadProgramHeaders validates the ELF header and returns the program header table, the size
// of one entry and the number of entries.
func elfReadProgramHeaders(path string, read func(offset int64, count int) ([]byte, bool)) ([]byte, int, int, error) {
	header, err := elfRead(path, read, 0, elfHeaderSize, "ELF header")
	if err != nil {
		return nil, 0, 0, err
	}
	if !bytes.Equal(header[:4], []byte{0x7F, 'E', 'L', 'F'}) {
		return nil, 0, 0, elfMalformed(path, "it is not an ELF file")
	}
	if header[4] != 2 || header[5] != 1 {
		return nil, 0, 0, elfMalformed(path, "it is not a 64-bit little-endian ELF file")
	}

	le := binary.LittleEndian
	programHeaderOffset, err := elfOffset(path, le.Uint64(header[32:]))
	if err != nil {
		return nil, 0, 0, err
	}
	programHeaderSize := int(le.Uint16(header[54:]))
	programHeaderCount := int(le.Uint16(header[56:]))
	if programHeaderSize < elfProgramHeaderSize || programHeaderCount == 0 || programHeaderCount > elfMaxProgramHeaders {
		return nil, 0, 0, elfMalformed(path, "its program header table is malformed")
	}
	// Both fields are 16-bit, so their product can reach 256 MB; bound the table like every other
	// region read, before anything is allocated for it.
	programHeaderBytes, err := elfSize(path, uint64(programHeaderSize)*uint64(programHeaderCount), "program header table")
	if err != nil {
		return nil, 0, 0, err
	}

	programHeaders, err := elfRead(path, read, programHeaderOffset, programHeaderBytes, "program headers")
	if err != nil {
		return nil, 0, 0, err
	}
	return programHeaders, programHeaderSize, programHeaderCount, nil
}

// elfReadNeeded parses DT_NEEDED names through read (see elfOpenReader). path names the file in
// errors.
func elfReadNeeded(path string, read func(offset int64, count int) ([]byte, bool)) ([]string, error) {
	programHeaders, programHeaderSize, programHeaderCount, err := elfReadProgramHeaders(path, read)
	if err != nil {
		return nil, err
	}

	le := binary.LittleEndian
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
