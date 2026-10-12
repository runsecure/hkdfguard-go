package nativev1

import (
	"strings"
	"testing"
)

func TestDEKLengthAndOK(t *testing.T) {
	if DEKLength != 32 || statusOK != 0 {
		t.Errorf("DEKLength = %d, statusOK = %d", DEKLength, statusOK)
	}
}

func requireDescribed(t *testing.T, table map[int32]string, statuses ...int32) {
	t.Helper()
	for _, status := range statuses {
		if table[status] == "" {
			t.Errorf("no description for %d", status)
		}
	}
}

func requireUndescribed(t *testing.T, table map[int32]string, statuses ...int32) {
	t.Helper()
	for _, status := range statuses {
		if description, ok := table[status]; ok {
			t.Errorf("%d is described as %q, want no description", status, description)
		}
	}
}

func TestWindowsStatuses_EveryDefinedOneIsDescribed_AndNothingElse(t *testing.T) {
	for status := int32(-14); status <= -1; status++ {
		requireDescribed(t, windowsStatusDescriptions, status)
	}
	requireUndescribed(t, windowsStatusDescriptions, -15, 1)

	accessDenied := windowsStatusDescriptions[winErrAccessDenied]
	if !strings.Contains(accessDenied, "not authorized") || !strings.Contains(accessDenied, "HkdfGuardUsers") {
		t.Errorf("access denied = %q", accessDenied)
	}
	if !strings.Contains(windowsStatusDescriptions[winErrKEKNotFound], "provision") {
		t.Errorf("KEK not found = %q", windowsStatusDescriptions[winErrKEKNotFound])
	}
}

func TestMacStatuses_EveryReturnedOneIsDescribed_ButNotTheReservedOnes(t *testing.T) {
	requireDescribed(t, macStatusDescriptions, -1, -2, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14, -15, -16, -17, -18)
	requireUndescribed(t, macStatusDescriptions, macErrKeyUnavailable, macErrPublicKeyUnavailable, -19)
}

func TestLinuxStatuses_EveryReturnedOneIsDescribed_ButNotTheReservedOrUnassignedOnes(t *testing.T) {
	requireDescribed(t, linuxStatusDescriptions, -1, -2, -3, -4, -5, -6, -8, -9, -16, -17)
	requireUndescribed(t, linuxStatusDescriptions, linuxErrInvalidUTF8, -10, -11, -12, -13, -14, -15, -18, 1)

	if !strings.Contains(linuxStatusDescriptions[linuxErrKEKNotFound], "provision") {
		t.Errorf("KEK not found = %q", linuxStatusDescriptions[linuxErrKEKNotFound])
	}
	if !strings.Contains(linuxStatusDescriptions[linuxErrFingerprintMismatch], "different KEK") {
		t.Errorf("fingerprint mismatch = %q", linuxStatusDescriptions[linuxErrFingerprintMismatch])
	}
}
