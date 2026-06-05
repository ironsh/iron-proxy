package postgres

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"
)

// authenticateClient runs the proxy-side cleartext password handshake against
// the connecting client.
//
// It expects the Backend to be positioned just after a StartupMessage was
// received (i.e. ready to send the first authentication challenge). On success
// the client has provided credentials matching the configured proxy creds, and
// no further protocol bytes have been written to the client.
//
// On failure, an ErrorResponse describing the auth failure has already been
// written to the client; callers should close the connection without further
// protocol exchange.
func authenticateClient(backend *pgproto3.Backend, startup *pgproto3.StartupMessage, upstream *Upstream) error {
	user := startup.Parameters["user"]
	if user == "" {
		writeFatal(backend, "28000", "no user provided in startup message")
		return errors.New("missing user in startup message")
	}
	if user != upstream.ClientUser() {
		writeFatal(backend, "28000", fmt.Sprintf("unknown user %q", user))
		return fmt.Errorf("unknown user %q", user)
	}

	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := backend.Flush(); err != nil {
		return fmt.Errorf("flushing auth challenge: %w", err)
	}

	msg, err := backend.Receive()
	if err != nil {
		return fmt.Errorf("receiving password message: %w", err)
	}
	pwMsg, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		writeFatal(backend, "08P01", "expected password message")
		return fmt.Errorf("expected PasswordMessage; got %T", msg)
	}

	if !upstream.VerifyClient(user, pwMsg.Password) {
		writeFatal(backend, "28P01", "password authentication failed")
		return errors.New("client password mismatch")
	}
	return nil
}

// writeFatal sends an ErrorResponse with severity FATAL to the client and
// flushes. Errors from flushing are ignored: by definition we are about to
// close the connection.
func writeFatal(backend *pgproto3.Backend, code, message string) {
	backend.Send(&pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     code,
		Message:  message,
	})
	_ = backend.Flush()
}

// randomBackendKey returns a (PID, secretKey) pair for the synthetic
// BackendKeyData the proxy advertises to its clients. The proxy does not
// support CancelRequest forwarding, so these values are not used for anything
// real — but the protocol requires them and they must not collide with the
// upstream's actual values lest the client think it can cancel directly.
func randomBackendKey() (uint32, []byte, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, nil, err
	}
	pid := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	secret := append([]byte(nil), buf[4:]...)
	return pid, secret, nil
}
