package nativev1

// errNoHardening is what every platform's library but Linux's returns from hardenProcess.
var errNoHardening = unsupported("The HkdfGuard native KMS library on this platform has no process hardening call; it is available on Linux only.")
