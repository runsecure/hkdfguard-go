package systemdcredentials

import (
	"fmt"
	"io"
	"os"

	"github.com/runsecure/hkdfguard-go"
)

// MaxLength is the largest credential read: systemd's own limit on a credential's size, 1 MiB.
const MaxLength = 1024 * 1024

const initialBufferLength = 4 * 1024

// Credential is a decrypted credential's value, in a []byte this package owns. Close it as soon as
// the value has been used: that wipes it, and any read afterwards fails with ErrClosed. Not safe
// for concurrent use with Close.
type Credential struct {
	buffer []byte
	length int
	closed bool
}

// Len is how many bytes the value is.
func (c *Credential) Len() int { return c.length }

// Value is the value; valid until the credential is closed, which wipes it. The slice is the
// credential's own: never keep it, or convert it to a string.
func (c *Credential) Value() ([]byte, error) {
	if c.closed {
		return nil, ErrClosed
	}
	return c.buffer[:c.length:c.length], nil
}

// Close wipes the value. Safe to call more than once.
func (c *Credential) Close() error {
	c.closed = true
	hkdfguard.Wipe(c.buffer)
	return nil
}

func tooLarge() error {
	return fmt.Errorf("%w: the credential is longer than systemd's %d-byte limit", ErrTooLarge, MaxLength)
}

// readCredential reads r to its end into a buffer that grows as needed, wiping each smaller buffer
// it drops. More than MaxLength bytes fail with ErrTooLarge, reading no more than one byte past it.
func readCredential(r io.Reader) (*Credential, error) {
	buffer := make([]byte, initialBufferLength)
	length := 0
	for {
		n, err := r.Read(buffer[length:])
		length += n
		if err == io.EOF {
			return &Credential{buffer: buffer, length: length}, nil
		}
		if err != nil {
			hkdfguard.Wipe(buffer)
			return nil, err
		}
		if length < len(buffer) {
			continue
		}
		if len(buffer) > MaxLength {
			hkdfguard.Wipe(buffer)
			return nil, tooLarge()
		}
		larger := make([]byte, min(2*len(buffer), MaxLength+1))
		copy(larger, buffer[:length])
		hkdfguard.Wipe(buffer)
		buffer = larger
	}
}

// readCredentialFile reads the file at path whole, unbuffered - os.File reads go straight to the
// kernel - so nothing but its page cache holds the value on the way.
func readCredentialFile(path string) (*Credential, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readCredentialFrom(file)
}

func readCredentialFrom(file *os.File) (*Credential, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxLength {
		return nil, tooLarge()
	}
	buffer := make([]byte, info.Size())
	read := 0
	for read < len(buffer) {
		n, err := file.ReadAt(buffer[read:], int64(read))
		read += n
		if err == io.EOF {
			break
		}
		if err != nil {
			hkdfguard.Wipe(buffer)
			return nil, err
		}
	}
	return &Credential{buffer: buffer, length: read}, nil
}
