package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mustPut runs Put on a handle and requires success.
func mustPut(t *testing.T, h Handle, blob CredentialBlob) {
	t.Helper()
	require.NoError(t, h.Put(t.Context(), blob))
}

func TestUnmarshalBlobRequiresRefreshToken(t *testing.T) {
	_, err := unmarshalBlob([]byte(`{"access_token":"abc","expires_at":"2026-01-01T00:00:00Z","last_refresh":"2026-01-01T00:00:00Z"}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "refresh_token")
}

func TestRoundTripBlob(t *testing.T) {
	expires := time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC)
	last := time.Date(2026, 5, 23, 23, 0, 0, 0, time.UTC)
	original := CredentialBlob{
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		ExpiresAt:    expires,
		LastRefresh:  last,
	}
	raw, err := marshalBlob(original)
	require.NoError(t, err)
	parsed, err := unmarshalBlob(raw)
	require.NoError(t, err)
	require.True(t, parsed.ExpiresAt.Equal(expires))
	require.True(t, parsed.LastRefresh.Equal(last))
	parsed.ExpiresAt = original.ExpiresAt
	parsed.LastRefresh = original.LastRefresh
	require.Equal(t, original, parsed)
}
