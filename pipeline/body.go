package pipeline

import (
	"io"

	"github.com/runsecure/hkdfguard-go"
)

// MaxBodyLength is the largest response body ReadBody reads: far beyond any secret store's
// response, so a larger one is refused.
const MaxBodyLength = 1024 * 1024

const initialBodyLength = 16 * 1024

// ReadBody reads a response body that holds a secret to its end into a buffer of its own - grown by
// copying and zeroing each smaller one, never through a bytes.Buffer or io.ReadAll, whose discarded
// arrays would keep the secret - for a store's writer to take it from: the Go port of the .NET
// PinnedBody. The caller must zero the buffer (hkdfguard.Wipe) once done. body is read but not
// closed.
//
// It fails with ErrInvalidArgument when body is nil, with ErrInvalidSecretData when the body is
// MaxBodyLength bytes or more, and with the reader's error when it can't be read; the buffer is
// zeroed, and nil returned, on any failure.
func ReadBody(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, invalidArgument("a body is required")
	}
	buffer := make([]byte, initialBodyLength)
	n := 0
	for {
		read, err := body.Read(buffer[n:])
		n += read
		if err == io.EOF {
			return buffer[:n], nil
		}
		if err != nil {
			hkdfguard.Wipe(buffer)
			return nil, err
		}
		if n < len(buffer) {
			continue
		}
		if len(buffer) >= MaxBodyLength {
			hkdfguard.Wipe(buffer)
			return nil, invalidData("the response body is %d bytes or more", MaxBodyLength)
		}
		larger := make([]byte, min(2*len(buffer), MaxBodyLength))
		copy(larger, buffer)
		hkdfguard.Wipe(buffer)
		buffer = larger
	}
}
