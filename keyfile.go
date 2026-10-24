package hkdfguard

import "errors"

// ErrInvalidKeyFile reports a key file a KeyWrapper's ReadKeyFile refused as not holding a
// wrapped key: the wrong size, holding what looks like an unwrapped key, or not a valid wrapped
// key.
var ErrInvalidKeyFile = errors.New("hkdfguard: invalid key file")
