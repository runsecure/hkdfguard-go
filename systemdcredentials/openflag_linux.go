package systemdcredentials

import "syscall"

// nonBlockingOpenFlag opens a FIFO without waiting for a writer, so it can be refused rather than
// block the open. A regular file reads as it always does.
const nonBlockingOpenFlag = syscall.O_NONBLOCK
