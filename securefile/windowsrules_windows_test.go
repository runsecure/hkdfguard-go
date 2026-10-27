//go:build windows

package securefile

import (
	"slices"
	"testing"

	"golang.org/x/sys/windows"
)

// The Windows rules against Windows itself: Windows parses the SDDL and SIDs, and names accounts.

// sddlSecurity is a descriptor written in SDDL, described as a real file's is.
func sddlSecurity(t *testing.T, sddl string) winSecurity {
	t.Helper()
	security, err := describeSecurity(windows.SecurityDescriptorFromString(sddl))
	if err != nil {
		t.Fatalf("%s: %v", sddl, err)
	}
	return security
}

func TestWindowsNative_CanonicalizesSids_AndAcceptsSddlAliases(t *testing.T) {
	principals, err := trustedPrincipals(NewKeyFileTrust(KeyFileTrustOptions{WindowsPrincipals: []string{"BA", "s-1-5-21-1111111111-2222222222-3333333333-1005"}}),
		canonicalSID, accountName)
	if err != nil {
		t.Fatal(err)
	}
	if got := principals[3:]; !slices.Equal(got, []string{sidAdministrators, sidDeployers}) {
		t.Errorf("got %v", got)
	}

	_, err = trustedPrincipals(NewKeyFileTrust(KeyFileTrustOptions{WindowsPrincipals: []string{"HkdfGuardDeployers"}}), canonicalSID, accountName)
	requireErrorContaining(t, err, ErrInvalidTrust, "not a security identifier")
	_, err = trustedPrincipals(NewKeyFileTrust(KeyFileTrustOptions{WindowsPrincipals: []string{"WD"}}), canonicalSID, accountName)
	requireErrorContaining(t, err, ErrInvalidTrust, "Everyone")
}

func TestWindowsNative_ParsesSddlDescriptorsAsTheRulesExpect(t *testing.T) {
	check := func(sddl string) error {
		return verifyTrustedOnly(sddlSecurity(t, sddl), windowsKeyFile, windowsKeyFile, guardedRights, testTrusted(t), accountName)
	}

	for _, sddl := range []string{"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200A9;;;BU)", "O:BAD:(A;;FA;;;BA)(D;;FA;;;BU)(A;OICIIO;0x1301BF;;;AU)"} {
		if err := check(sddl); err != nil {
			t.Errorf("%s: %v", sddl, err)
		}
	}
	for _, refused := range [][2]string{
		{"O:BUD:(A;;FA;;;SY)", "is owned by"},
		{"D:(A;;FA;;;SY)", "an unknown principal"},
		{"O:BAD:NO_ACCESS_CONTROL", "no DACL"},
		{"O:BAD:(A;;FA;;;SY)(A;;GA;;;BU)", "grants"}, // unmapped generic rights
		{"O:BAD:(A;;FA;;;SY)(A;;GW;;;BU)", "grants"},
		{"O:BAD:(A;;FA;;;SY)(OA;;0x2;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)", "can't evaluate"}, // an allow-object ACE
	} {
		requireUntrusted(t, check(refused[0]), refused[1])
	}
}

func TestWindowsNative_DescribesAnUnmappableSidByItsValue_AndNamesAMappableOne(t *testing.T) {
	security := sddlSecurity(t, "O:BAD:(A;;FA;;;SY)(A;;0x116;;;"+sidDeployers+")")
	requireUntrusted(t, verifyTrustedOnly(security, windowsKeyFile, windowsKeyFile, guardedRights, testTrusted(t), accountName), "to "+sidDeployers+".")
	if accountName(sidAdministrators) == "" {
		t.Error("Administrators has no account name")
	}
	if accountName("not a SID") != "" {
		t.Error("an invalid SID has an account name")
	}
}

func TestWindowsNative_RefusesInvalidSddl_AndAStringHoldingNul(t *testing.T) {
	if _, err := windows.SecurityDescriptorFromString("not SDDL"); err == nil {
		t.Error("invalid SDDL was parsed")
	}
	if _, ok := canonicalSID("S-1-5-18\x00"); ok {
		t.Error("a SID holding NUL was accepted")
	}
}
