package secrets

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type smallChunkReadCloser struct {
	reader *strings.Reader
	size   int
}

func (r *smallChunkReadCloser) Read(p []byte) (int, error) {
	if len(p) > r.size {
		p = p[:r.size]
	}
	return r.reader.Read(p)
}

func (*smallChunkReadCloser) Close() error { return nil }

func TestReplacingReadCloser(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		chunkSize    int
		replacements []responseReplacement
		want         string
	}{
		{
			name:      "split across reads",
			input:     "before real-vault-secret after",
			chunkSize: 3,
			replacements: []responseReplacement{
				{upstream: "real-vault-secret", client: "proxy-vault-secret"},
			},
			want: "before proxy-vault-secret after",
		},
		{
			name:      "multiple and overlapping values",
			input:     "Bearer real and real",
			chunkSize: 2,
			replacements: []responseReplacement{
				{upstream: "real", client: "proxy"},
				{upstream: "Bearer real", client: "Bearer proxy"},
			},
			want: "Bearer proxy and proxy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := &smallChunkReadCloser{reader: strings.NewReader(tc.input), size: tc.chunkSize}
			reader := newReplacingReadCloser(source, tc.replacements)
			got, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(got))
			require.NoError(t, reader.Close())
		})
	}
}
