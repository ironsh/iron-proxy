package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDialUpstreamDatabaseMismatch verifies dialUpstream refuses a DSN whose
// database differs from the upstream's routing database. The mismatch is caught
// after parsing the DSN but before any network round-trip, so this needs no
// server.
func TestDialUpstreamDatabaseMismatch(t *testing.T) {
	up, err := NewManagedUpstream("appdb",
		staticDSN{name: "dsn", value: "host=127.0.0.1 port=1 dbname=otherdb"}, "u", "p", "")
	require.NoError(t, err)

	_, err = dialUpstream(context.Background(), up)
	require.Error(t, err)
	var mismatch *databaseMismatchError
	require.True(t, errors.As(err, &mismatch), "want databaseMismatchError, got %v", err)
	require.Equal(t, "appdb", mismatch.configured)
	require.Equal(t, "otherdb", mismatch.dsn)
}

// TestDialUpstreamMissingDatabase verifies dialUpstream refuses a DSN that does
// not name a database. Caught before any network round-trip.
func TestDialUpstreamMissingDatabase(t *testing.T) {
	up, err := NewManagedUpstream("appdb",
		staticDSN{name: "dsn", value: "host=127.0.0.1 port=1 user=app"}, "u", "p", "")
	require.NoError(t, err)

	_, err = dialUpstream(context.Background(), up)
	require.Error(t, err)
	var missing *missingDSNDatabaseError
	require.True(t, errors.As(err, &missing), "want missingDSNDatabaseError, got %v", err)
	require.Equal(t, "appdb", missing.configured)
}

// TestDialUpstreamDatabaseMatchPassesCheck verifies that a DSN whose database
// matches the routing database clears the check. The dial still fails (nothing
// is listening on port 1), but the failure must not be a databaseMismatchError.
func TestDialUpstreamDatabaseMatchPassesCheck(t *testing.T) {
	up, err := NewManagedUpstream("appdb",
		staticDSN{name: "dsn", value: "host=127.0.0.1 port=1 dbname=appdb"}, "u", "p", "")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = dialUpstream(ctx, up)
	require.Error(t, err)
	var mismatch *databaseMismatchError
	require.False(t, errors.As(err, &mismatch), "database matched; should not be a mismatch error: %v", err)
}
