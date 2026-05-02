package hint

import (
	"reflect"
	"testing"
)

func TestDedupe(t *testing.T) {
	tests := []struct {
		name string
		in   []Hint
		want []Hint
	}{
		{
			name: "empty input",
			in:   nil,
			want: nil,
		},
		{
			name: "single hint",
			in:   []Hint{{Type: RedundantCd, Message: "a"}},
			want: []Hint{{Type: RedundantCd, Message: "a"}},
		},
		{
			name: "duplicate same type and message",
			in: []Hint{
				{Type: RedundantCd, Message: "cd /x is unnecessary"},
				{Type: RedundantCd, Message: "cd /x is unnecessary"},
				{Type: RedundantCd, Message: "cd /x is unnecessary"},
			},
			want: []Hint{
				{Type: RedundantCd, Message: "cd /x is unnecessary"},
			},
		},
		{
			name: "preserves first occurrence order",
			in: []Hint{
				{Type: RedundantCd, Message: "a"},
				{Type: AbsolutePathConvertible, Message: "b"},
				{Type: RedundantCd, Message: "a"},
				{Type: AbsolutePathConvertible, Message: "c"},
				{Type: AbsolutePathConvertible, Message: "b"},
			},
			want: []Hint{
				{Type: RedundantCd, Message: "a"},
				{Type: AbsolutePathConvertible, Message: "b"},
				{Type: AbsolutePathConvertible, Message: "c"},
			},
		},
		{
			name: "same message different type kept distinct",
			in: []Hint{
				{Type: RedundantCd, Message: "x"},
				{Type: AbsolutePathConvertible, Message: "x"},
			},
			want: []Hint{
				{Type: RedundantCd, Message: "x"},
				{Type: AbsolutePathConvertible, Message: "x"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Dedupe(tt.in)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Dedupe(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
