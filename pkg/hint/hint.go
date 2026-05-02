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

// Dedupe returns hints with duplicates removed, preserving first occurrence order.
// Two hints are considered duplicates when they share the same Type and Message.
func Dedupe(hints []Hint) []Hint {
	if len(hints) == 0 {
		return hints
	}
	type key struct {
		t Type
		m string
	}
	seen := make(map[key]struct{}, len(hints))
	out := make([]Hint, 0, len(hints))
	for _, h := range hints {
		k := key{t: h.Type, m: h.Message}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, h)
	}
	return out
}
