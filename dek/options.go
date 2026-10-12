package dek

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/runsecure/hkdfguard-go"
)

// MaxEphemeralKeyRotationHours is the largest Options.EphemeralKeyRotationHours - the .NET port's
// timer limit, kept here so one configuration file is valid for every port.
const MaxEphemeralKeyRotationHours = 1193

// ErrInvalidOptions reports Options that break a rule; the error lists every rule broken.
var ErrInvalidOptions = errors.New("dek: invalid options")

// Options is the file-loadable form of Config: plain data, in the units and with the field names
// of the .NET port's HkdfGuardOptions, so the same "HkdfGuard" section of an appsettings.json
// configures both ports. It carries no behavior: the KeyWrapper and CryptoProviderFactory a ring
// needs are supplied to Config, which turns Options into a Config.
type Options struct {
	// ServiceName identifies this ring's KEK to the native KMS library. Required.
	ServiceName string `json:"ServiceName"`

	// KeyRefreshInterval is how often, in seconds (1-300), each key is re-revealed through the KEK.
	// Unset here, it must be set on the Config before Build.
	KeyRefreshInterval *int `json:"KeyRefreshInterval,omitempty"`

	// MaxRefreshFailures is how many consecutive failed refreshes a key tolerates before failing
	// closed; at least 1. Unset keeps hkdfguard.DefaultMaxRefreshFailures. Can't be combined with
	// FailOpenOnRefreshFailure.
	MaxRefreshFailures *int `json:"MaxRefreshFailures,omitempty"`

	// FailOpenOnRefreshFailure keeps the last good key in use however many refreshes fail.
	FailOpenOnRefreshFailure bool `json:"FailOpenOnRefreshFailure,omitempty"`

	// EphemeralKeyRotationHours is how many hours (1 to MaxEphemeralKeyRotationHours) between
	// ephemeral key rotations. Unset keeps DefaultEphemeralKeyRotation. Can't be combined with
	// DisableEphemeralKeyRotation.
	EphemeralKeyRotationHours *int `json:"EphemeralKeyRotationHours,omitempty"`

	// DisableEphemeralKeyRotation keeps the ephemeral key built at startup current.
	DisableEphemeralKeyRotation bool `json:"DisableEphemeralKeyRotation,omitempty"`

	// EphemeralKeyRetentionHours is how many hours (at least 1) a superseded ephemeral key stays
	// registered for decryption. Unset keeps DefaultEphemeralKeyRetention.
	EphemeralKeyRetentionHours *int `json:"EphemeralKeyRetentionHours,omitempty"`

	// KeyFiles are versions whose wrapped DEK is read from a file.
	KeyFiles []KeyFileOptions `json:"KeyFiles,omitempty"`

	// EphemeralKeys are versions whose DEK is generated at startup and never written to disk.
	EphemeralKeys []int `json:"EphemeralKeys,omitempty"`
}

// KeyFileOptions pairs a version with the path of its wrapped DEK file.
type KeyFileOptions struct {
	Version int    `json:"Version"`
	Path    string `json:"Path"`
}

// Validate checks every rule Build enforces, plus what can be caught earlier with a clearer
// message: a valid ServiceName, a path for every key file, and no version registered twice. It
// returns nil, or an error wrapping ErrInvalidOptions that lists every rule broken.
func (o Options) Validate() error {
	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }

	if strings.TrimSpace(o.ServiceName) == "" {
		fail("ServiceName is invalid: A service name is required.")
	} else if err := hkdfguard.ValidateServiceName(o.ServiceName); err != nil {
		fail("ServiceName is invalid: %s", strings.TrimPrefix(err.Error(), hkdfguard.ErrInvalidServiceName.Error()+": "))
	}

	if o.KeyRefreshInterval != nil && (*o.KeyRefreshInterval < 1 || *o.KeyRefreshInterval > 300) {
		fail("KeyRefreshInterval must be between 1 and 300 seconds.")
	}
	if o.MaxRefreshFailures != nil && *o.MaxRefreshFailures < 1 {
		fail("MaxRefreshFailures must be at least 1.")
	}
	if o.EphemeralKeyRotationHours != nil && (*o.EphemeralKeyRotationHours < 1 || *o.EphemeralKeyRotationHours > MaxEphemeralKeyRotationHours) {
		fail("EphemeralKeyRotationHours must be between 1 and %d.", MaxEphemeralKeyRotationHours)
	}
	if o.EphemeralKeyRetentionHours != nil && *o.EphemeralKeyRetentionHours < 1 {
		fail("EphemeralKeyRetentionHours must be at least 1.")
	}
	if o.DisableEphemeralKeyRotation && o.EphemeralKeyRotationHours != nil {
		fail("DisableEphemeralKeyRotation and EphemeralKeyRotationHours can't both be set: one turns rotation off, the other schedules it.")
	}
	if o.FailOpenOnRefreshFailure && o.MaxRefreshFailures != nil {
		fail("FailOpenOnRefreshFailure and MaxRefreshFailures can't both be set: one fails open, the other fails closed.")
	}
	if len(o.KeyFiles) == 0 && len(o.EphemeralKeys) == 0 {
		fail("At least one key file or ephemeral key is required.")
	}

	seen := map[int]int{}
	var order []int
	for _, keyFile := range o.KeyFiles {
		if strings.TrimSpace(keyFile.Path) == "" {
			fail("KeyFiles version %d is missing a path.", keyFile.Version)
		}
		if seen[keyFile.Version]++; seen[keyFile.Version] == 2 {
			order = append(order, keyFile.Version)
		}
	}
	for _, version := range o.EphemeralKeys {
		if seen[version]++; seen[version] == 2 {
			order = append(order, version)
		}
	}
	for _, version := range order {
		fail("Version %d is registered more than once across KeyFiles/EphemeralKeys.", version)
	}

	if len(failures) == 0 {
		return nil
	}
	return fmt.Errorf("%w:\n  %s", ErrInvalidOptions, strings.Join(failures, "\n  "))
}

// Config validates o and returns the Config it describes, with keyWrapper and factory - the
// behavior Options can't carry as data. Settings o leaves unset keep Config's defaults. Further
// fields (FormatProvider, Logger) can be set on the result before calling Build.
func (o Options) Config(keyWrapper hkdfguard.KeyWrapper, factory hkdfguard.CryptoProviderFactory) (Config, error) {
	if err := o.Validate(); err != nil {
		return Config{}, err
	}

	config := Config{
		KeyWrapper:                  keyWrapper,
		CryptoProviderFactory:       factory,
		ServiceName:                 o.ServiceName,
		DisableEphemeralKeyRotation: o.DisableEphemeralKeyRotation,
		EphemeralKeys:               append([]int(nil), o.EphemeralKeys...),
	}
	if o.KeyRefreshInterval != nil {
		config.KeyRefreshInterval = time.Duration(*o.KeyRefreshInterval) * time.Second
	}
	switch {
	case o.FailOpenOnRefreshFailure:
		config.RefreshFailurePolicy = hkdfguard.FailOpen()
	case o.MaxRefreshFailures != nil:
		config.RefreshFailurePolicy = hkdfguard.FailClosedAfter(*o.MaxRefreshFailures)
	}
	if o.EphemeralKeyRotationHours != nil {
		config.EphemeralKeyRotation = time.Duration(*o.EphemeralKeyRotationHours) * time.Hour
	}
	if o.EphemeralKeyRetentionHours != nil {
		config.EphemeralKeyRetention = time.Duration(*o.EphemeralKeyRetentionHours) * time.Hour
	}
	if len(o.KeyFiles) > 0 {
		config.KeyFiles = make(map[int]string, len(o.KeyFiles))
		for _, keyFile := range o.KeyFiles {
			config.KeyFiles[keyFile.Version] = keyFile.Path
		}
	}
	return config, nil
}

// OptionsFromJSON reads Options from section of a JSON document - e.g. the "HkdfGuard" section of
// an appsettings.json, or a nested path such as "Security:HkdfGuard". Section names match ignoring
// case, and an empty section reads the whole document. Field names match ignoring case and unknown
// fields are ignored, as .NET's configuration binder does. The result is not validated; Config
// does that.
func OptionsFromJSON(document []byte, section string) (Options, error) {
	raw := json.RawMessage(document)
	if section != "" {
		for _, name := range strings.Split(section, ":") {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(raw, &object); err != nil {
				return Options{}, fmt.Errorf("dek: reading options section '%s': %w", section, err)
			}
			found := false
			for key, value := range object {
				if strings.EqualFold(key, name) {
					raw, found = value, true
					break
				}
			}
			if !found {
				return Options{}, fmt.Errorf("dek: the JSON document has no '%s' section", section)
			}
		}
	}

	var options Options
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&options); err != nil {
		return Options{}, fmt.Errorf("dek: reading options section '%s': %w", section, err)
	}
	return options, nil
}
