package configurationresolver

import "errors"

const (
	// DefaultStartSequence is the default sequence that marks the start of a configuration item.
	DefaultStartSequence = "${"

	// DefaultEndSequence is the default sequence that marks the end of a configuration item.
	DefaultEndSequence = "}"

	// DefaultEscapeSequence is the escape sequence of NewDefaultToken, so that "$${Name}" is
	// written as the literal text "${Name}".
	DefaultEscapeSequence = "$"
)

// ConfigurationItemToken identifies configuration items delimited by a start and an end sequence,
// such as ${Name}: the port of ConfigurationItemTokenBase. Use the same token for a reader and the
// resolver given that reader. A token is immutable and safe for concurrent use.
type ConfigurationItemToken struct {
	start  string
	end    string
	escape string
}

// NewConfigurationItemToken returns a token with the given sequences. escape, written directly
// before a start sequence, makes it literal text instead of the start of an item; "" means the
// token has no escape sequence. It fails when start or end is empty.
func NewConfigurationItemToken(start, end, escape string) (*ConfigurationItemToken, error) {
	if start == "" || end == "" {
		return nil, errors.New("configurationresolver: a token's start and end sequences cannot be empty")
	}
	return &ConfigurationItemToken{start: start, end: end, escape: escape}, nil
}

// NewDefaultToken returns the token that uses "${" and "}", with "$" as its escape sequence, so
// "$${Name}" is written as the literal text "${Name}": the port of DefaultToken.
func NewDefaultToken() *ConfigurationItemToken {
	return &ConfigurationItemToken{start: DefaultStartSequence, end: DefaultEndSequence, escape: DefaultEscapeSequence}
}

// StartSequence is the sequence that marks the start of a configuration item.
func (t *ConfigurationItemToken) StartSequence() string { return t.start }

// EndSequence is the sequence that marks the end of a configuration item.
func (t *ConfigurationItemToken) EndSequence() string { return t.end }

// EscapeSequence is the sequence that, directly before a start sequence, makes it literal text, or
// "" if the token has none.
//
// The escape sequence is removed and the start sequence is copied as text, so with the escape
// sequence "$", "$${Name}" is written as "${Name}" and Name is not a key. Only the start sequence
// is escaped: the text after it is read as usual, so it can contain other items. An escape
// sequence anywhere else is ordinary text.
func (t *ConfigurationItemToken) EscapeSequence() string { return t.escape }
