package hint

// Type identifies the kind of token-saving hint.
type Type int

const (
	// RedundantCd indicates an unnecessary cd to the current working directory.
	RedundantCd Type = iota
	// AbsolutePathConvertible indicates an absolute path that could be relative.
	AbsolutePathConvertible
)

// Hint represents a single token-saving suggestion.
type Hint struct {
	Type    Type
	Message string
}
