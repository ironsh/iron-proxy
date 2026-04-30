package dnsguard

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew_RejectsBareIPs(t *testing.T) {
	tests := []string{
		"1.2.3.4",
		"169.254.169.254",
		"::1",
		"fd00:ec2::254",
	}
	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			_, err := New([]string{in})
			require.Error(t, err)
			require.Contains(t, err.Error(), "must be CIDR notation")
		})
	}
}

func TestNew_RejectsMalformed(t *testing.T) {
	tests := []string{
		"not-an-ip/24",
		"999.999.999.999/32",
		"10.0.0.0/99",
		"  ",
	}
	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			_, err := New([]string{in})
			require.Error(t, err)
		})
	}
}

func TestNew_AcceptsValid(t *testing.T) {
	g, err := New([]string{
		"169.254.169.254/32",
		"127.0.0.0/8",
		"::1/128",
		"fd00:ec2::254/128",
		"10.0.0.0/8",
	})
	require.NoError(t, err)
	require.NotNil(t, g)
}

func TestNew_NilAndEmpty(t *testing.T) {
	g, err := New(nil)
	require.NoError(t, err)
	require.False(t, g.IsDenied(netip.MustParseAddr("169.254.169.254")))

	g, err = New([]string{})
	require.NoError(t, err)
	require.False(t, g.IsDenied(netip.MustParseAddr("127.0.0.1")))
}

func TestIsDenied(t *testing.T) {
	g, err := New([]string{
		"169.254.169.254/32",
		"127.0.0.0/8",
		"::1/128",
	})
	require.NoError(t, err)

	denied := []string{
		"169.254.169.254",
		"127.0.0.1",
		"127.255.255.254",
		"::1",
	}
	for _, ip := range denied {
		t.Run("denied/"+ip, func(t *testing.T) {
			require.True(t, g.IsDenied(netip.MustParseAddr(ip)))
		})
	}

	allowed := []string{
		"169.254.169.253",
		"169.254.170.0",
		"128.0.0.0",
		"8.8.8.8",
		"::2",
		"2001:db8::1",
	}
	for _, ip := range allowed {
		t.Run("allowed/"+ip, func(t *testing.T) {
			require.False(t, g.IsDenied(netip.MustParseAddr(ip)))
		})
	}
}

func TestIsDenied_4in6Mapped(t *testing.T) {
	g, err := New([]string{"127.0.0.0/8"})
	require.NoError(t, err)

	mapped := netip.MustParseAddr("::ffff:127.0.0.1")
	require.True(t, g.IsDenied(mapped))
}

func TestDialControl_DenyAndAllow(t *testing.T) {
	g, err := New([]string{"127.0.0.0/8", "169.254.169.254/32"})
	require.NoError(t, err)

	t.Run("denied ipv4", func(t *testing.T) {
		err := g.DialControl("tcp", "127.0.0.1:443", nil)
		require.Error(t, err)
		require.True(t, IsDenyError(err))
	})

	t.Run("denied imds", func(t *testing.T) {
		err := g.DialControl("tcp", "169.254.169.254:80", nil)
		require.Error(t, err)
		var de *DenyError
		require.ErrorAs(t, err, &de)
		require.Equal(t, "169.254.169.254", de.Address)
	})

	t.Run("allowed ipv4", func(t *testing.T) {
		require.NoError(t, g.DialControl("tcp", "8.8.8.8:443", nil))
	})

	t.Run("4-in-6 mapped denied", func(t *testing.T) {
		err := g.DialControl("tcp", "[::ffff:127.0.0.1]:443", nil)
		require.Error(t, err)
		require.True(t, IsDenyError(err))
	})

	t.Run("malformed address allowed", func(t *testing.T) {
		// Not our job to reject malformed addresses — Go's connect will fail.
		require.NoError(t, g.DialControl("tcp", "not-an-address", nil))
	})
}

func TestDialControl_EmptyGuardNoop(t *testing.T) {
	g, err := New(nil)
	require.NoError(t, err)
	require.NoError(t, g.DialControl("tcp", "127.0.0.1:443", nil))
}

func TestDialControl_NilGuardNoop(t *testing.T) {
	var g *Guard
	require.NoError(t, g.DialControl("tcp", "127.0.0.1:443", nil))
}
