package dek

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

func intPtr(v int) *int { return &v }

func validOptions() Options {
	return Options{ServiceName: "com.example.orders", KeyRefreshInterval: intPtr(60), EphemeralKeys: []int{1}}
}

// requireInvalid asserts o fails validation naming every reason.
func requireInvalid(t *testing.T, o Options, reasons ...string) {
	t.Helper()
	err := o.Validate()
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("Validate = %v, want ErrInvalidOptions", err)
	}
	for _, reason := range reasons {
		if !strings.Contains(err.Error(), reason) {
			t.Errorf("%q does not mention %q", err, reason)
		}
	}
}

func TestOptions_Valid_Passes(t *testing.T) {
	o := validOptions()
	o.KeyFiles = []KeyFileOptions{{Version: 1, Path: "/etc/app/key.v1"}}
	o.EphemeralKeys = []int{2}
	o.MaxRefreshFailures = intPtr(hkdfguard.MaxAllowedRefreshFailures)
	o.EphemeralKeyRotationHours = intPtr(MaxEphemeralKeyRotationHours)
	o.EphemeralKeyRetentionHours = intPtr(24 * 365)

	if err := o.Validate(); err != nil {
		t.Error(err)
	}
}

func TestOptions_ServiceName_IsRequiredAndValidated(t *testing.T) {
	for _, name := range []string{"", "   "} {
		o := validOptions()
		o.ServiceName = name
		requireInvalid(t, o, "ServiceName is invalid", "required")
	}
	reasons := map[string]string{".service": "can't start with '.'", "my..service": "can't contain '..'", "my-service": "U+002D", strings.Repeat("a", 129): "at most 128"}
	for name, reason := range reasons {
		o := validOptions()
		o.ServiceName = name
		requireInvalid(t, o, "ServiceName is invalid: ", reason)
	}
}

func TestOptions_RangesAreChecked(t *testing.T) {
	cases := []struct {
		mutate func(*Options)
		reason string
	}{
		{func(o *Options) { o.KeyRefreshInterval = intPtr(0) }, "KeyRefreshInterval must be between 1 and 300"},
		{func(o *Options) { o.KeyRefreshInterval = intPtr(301) }, "KeyRefreshInterval must be between 1 and 300"},
		{func(o *Options) { o.MaxRefreshFailures = intPtr(0) }, "MaxRefreshFailures must be between 1 and 100"},
		{func(o *Options) { o.MaxRefreshFailures = intPtr(101) }, "MaxRefreshFailures must be between 1 and 100"},
		{func(o *Options) { o.EphemeralKeyRotationHours = intPtr(0) }, "EphemeralKeyRotationHours must be between 1 and 1193"},
		{func(o *Options) { o.EphemeralKeyRotationHours = intPtr(MaxEphemeralKeyRotationHours + 1) }, "EphemeralKeyRotationHours must be between 1 and 1193"},
		{func(o *Options) { o.EphemeralKeyRetentionHours = intPtr(-1) }, "EphemeralKeyRetentionHours must be at least 1"},
	}
	for _, c := range cases {
		o := validOptions()
		c.mutate(&o)
		requireInvalid(t, o, c.reason)
	}

	for _, interval := range []int{1, 300} {
		o := validOptions()
		o.KeyRefreshInterval = intPtr(interval)
		if err := o.Validate(); err != nil {
			t.Errorf("interval %d: %v", interval, err)
		}
	}
	unset := validOptions()
	unset.KeyRefreshInterval = nil
	if err := unset.Validate(); err != nil {
		t.Errorf("unset interval: %v", err)
	}
}

func TestOptions_ContradictorySettings_AreRefused(t *testing.T) {
	o := validOptions()
	o.DisableEphemeralKeyRotation, o.EphemeralKeyRotationHours = true, intPtr(6)
	requireInvalid(t, o, "DisableEphemeralKeyRotation and EphemeralKeyRotationHours can't both be set")

	o = validOptions()
	o.FailOpenOnRefreshFailure, o.MaxRefreshFailures = true, intPtr(3)
	requireInvalid(t, o, "FailOpenOnRefreshFailure and MaxRefreshFailures can't both be set")

	for _, alone := range []func(*Options){
		func(o *Options) { o.DisableEphemeralKeyRotation = true },
		func(o *Options) { o.FailOpenOnRefreshFailure = true },
	} {
		o := validOptions()
		alone(&o)
		if err := o.Validate(); err != nil {
			t.Error(err)
		}
	}
}

func TestOptions_KeysAreChecked(t *testing.T) {
	o := validOptions()
	o.EphemeralKeys = nil
	requireInvalid(t, o, "At least one key file or ephemeral key is required")

	o = validOptions()
	o.KeyFiles = []KeyFileOptions{{Version: 2, Path: " "}}
	requireInvalid(t, o, "KeyFiles version 2 is missing a path")

	o = validOptions()
	o.KeyFiles = []KeyFileOptions{{Version: 1, Path: "/a"}, {Version: 2, Path: "/b"}, {Version: 2, Path: "/c"}}
	requireInvalid(t, o, "Version 1 is registered more than once", "Version 2 is registered more than once")
}

func TestOptions_AKeyFileAboveEveryEphemeralVersion_IsRefusedWhileRotating(t *testing.T) {
	o := validOptions()
	o.KeyFiles = []KeyFileOptions{{Version: 3, Path: "/etc/app/key.v3"}, {Version: 2, Path: "/etc/app/key.v2"}}
	requireInvalid(t, o, "KeyFiles version 3 is above every ephemeral version")

	o.DisableEphemeralKeyRotation = true
	if err := o.Validate(); err != nil {
		t.Errorf("with rotation disabled: %v", err)
	}
}

func TestOptions_ReportEveryFailureAtOnce(t *testing.T) {
	requireInvalid(t, Options{KeyRefreshInterval: intPtr(0)},
		"ServiceName is invalid", "KeyRefreshInterval must be", "At least one key file")
}

func TestOptions_Config_CarriesEverySetting(t *testing.T) {
	f := &recordingFactory{t: t}
	o := Options{
		ServiceName:                "com.example.orders",
		KeyRefreshInterval:         intPtr(30),
		MaxRefreshFailures:         intPtr(5),
		EphemeralKeyRotationHours:  intPtr(6),
		EphemeralKeyRetentionHours: intPtr(48),
		KeyFiles:                   []KeyFileOptions{{Version: 1, Path: "/etc/app/key.v1"}},
		EphemeralKeys:              []int{2},
	}

	config, err := o.Config(nopKeyWrapper{}, f)
	if err != nil {
		t.Fatal(err)
	}

	limit, failsClosed := config.RefreshFailurePolicy.MaxFailures()
	switch {
	case config.KeyWrapper != (nopKeyWrapper{}) || config.CryptoProviderFactory != f:
		t.Error("behavior not carried")
	case config.ServiceName != "com.example.orders" || config.KeyRefreshInterval != 30*time.Second:
		t.Errorf("service %q, interval %v", config.ServiceName, config.KeyRefreshInterval)
	case !failsClosed || limit != 5:
		t.Errorf("policy %v", config.RefreshFailurePolicy)
	case config.EphemeralKeyRotation != 6*time.Hour || config.EphemeralKeyRetention != 48*time.Hour:
		t.Errorf("rotation %v, retention %v", config.EphemeralKeyRotation, config.EphemeralKeyRetention)
	case config.KeyFiles[1] != "/etc/app/key.v1" || !slices.Equal(config.EphemeralKeys, []int{2}):
		t.Errorf("keys %v, %v", config.KeyFiles, config.EphemeralKeys)
	}
}

func TestOptions_Config_LeavesUnsetSettingsAtTheirDefaults(t *testing.T) {
	config, err := Options{ServiceName: "svc", EphemeralKeys: []int{1}}.Config(nopKeyWrapper{}, &recordingFactory{t: t})
	if err != nil {
		t.Fatal(err)
	}

	if limit, failsClosed := config.RefreshFailurePolicy.MaxFailures(); !failsClosed || limit != hkdfguard.DefaultMaxRefreshFailures {
		t.Errorf("policy %v", config.RefreshFailurePolicy)
	}
	if config.EphemeralKeyRotation != 0 || config.EphemeralKeyRetention != 0 || config.DisableEphemeralKeyRotation {
		t.Error("rotation settings changed from their defaults")
	}
	if config.KeyRefreshInterval != 0 {
		t.Errorf("interval = %v", config.KeyRefreshInterval)
	}
}

func TestOptions_Config_FailOpenAndDisabledRotation(t *testing.T) {
	config, _ := Options{ServiceName: "svc", EphemeralKeys: []int{1}, FailOpenOnRefreshFailure: true, DisableEphemeralKeyRotation: true}.
		Config(nopKeyWrapper{}, &recordingFactory{t: t})

	if _, failsClosed := config.RefreshFailurePolicy.MaxFailures(); failsClosed || !config.DisableEphemeralKeyRotation {
		t.Errorf("policy %v, disabled %v", config.RefreshFailurePolicy, config.DisableEphemeralKeyRotation)
	}
}

func TestOptions_Config_RefusesInvalidOptions(t *testing.T) {
	if _, err := (Options{}).Config(nopKeyWrapper{}, &recordingFactory{t: t}); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("error = %v", err)
	}
}

func TestOptions_FromAnAppSettingsFile_BuildAWorkingRing(t *testing.T) {
	keyFile := writeKeyFile(t, []byte("wrapped"))
	document := []byte(`{
		"Logging": { "LogLevel": { "Default": "Information" } },
		"Security": {
			"hkdfguard": {
				"serviceName": "com.example.orders",
				"KeyRefreshInterval": 60,
				"MaxRefreshFailures": 4,
				"KeyFiles": [ { "Version": 1, "Path": ` + jsonString(keyFile) + ` } ],
				"EphemeralKeys": [ 2 ],
				"SomeSettingThisPortDoesNotKnow": true
			}
		}
	}`)

	options, err := OptionsFromJSON(document, "Security:HkdfGuard")
	if err != nil {
		t.Fatal(err)
	}
	f := &recordingFactory{t: t}
	config, err := options.Config(nopKeyWrapper{}, f)
	if err != nil {
		t.Fatal(err)
	}
	ring := mustBuild(t, config)

	requireCurrent(t, ring, 2)
	if _, ok := ring.TryGet(bg, 1); !ok {
		t.Error("the key file's version is not registered")
	}
	if limit, _ := f.policies[0].MaxFailures(); limit != 4 || f.expiries[0] != time.Minute {
		t.Errorf("providers got %v and %v", f.policies[0], f.expiries[0])
	}
}

func jsonString(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func TestOptionsFromJSON_ReportsAMissingSectionOrBadJSON(t *testing.T) {
	cases := map[string]struct{ document, section string }{
		"missing section":       {`{"Other":{}}`, "HkdfGuard"},
		"missing nested":        {`{"Security":{}}`, "Security:HkdfGuard"},
		"not JSON":              {`{"HkdfGuard":`, "HkdfGuard"},
		"section not an object": {`{"Security":"x"}`, "Security:HkdfGuard"},
		"wrong field type":      {`{"HkdfGuard":{"KeyRefreshInterval":"sixty"}}`, "HkdfGuard"},
	}
	for name, c := range cases {
		if _, err := OptionsFromJSON([]byte(c.document), c.section); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	whole, err := OptionsFromJSON([]byte(`{"ServiceName":"svc","EphemeralKeys":[1]}`), "")
	if err != nil || whole.ServiceName != "svc" {
		t.Errorf("whole document: %+v, %v", whole, err)
	}
}
