package hostmatch

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "bar.baz.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "notexample.com", false},
		{"exact.example.com", "exact.example.com", true},
		{"exact.example.com", "other.example.com", false},
		{"*", "anything.example.com", true},
		{"*", "1.2.3.4", true},
		{"*", "", true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.pattern, tt.name), func(t *testing.T) {
			require.Equal(t, tt.want, MatchGlob(tt.pattern, tt.name))
		})
	}
}
