package hkdfguard

import "runtime"

// Secret-memory helpers - the Go port of the .NET ArrayUtility.
//
// Go has no pinned allocation and no stackalloc, so the .NET guarantee that zeroing reaches the
// only copy of a secret is best-effort here: Go's garbage collector does not move heap objects
// today, but goroutine stacks are copied when they grow. Keep secrets in heap-allocated []byte
// buffers (never in a string, which can't be zeroed), and Wipe them as soon as they are no longer
// needed.

// Wipe zeroes every byte of b. The runtime.KeepAlive keeps b live until the clear has run, so
// the compiler can't treat the stores as dead and drop them.
func Wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// IsZero reports whether b is empty or every byte is zero. Its running time depends only on
// len(b), never on the contents, so it is safe to call on key material.
func IsZero(b []byte) bool {
	var accumulator byte
	for _, c := range b {
		accumulator |= c
	}
	return accumulator == 0
}
