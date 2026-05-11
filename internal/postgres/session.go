package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// probeIterations is how many SELECT current_role probes the proxy runs in
// separate autocommit Simple Queries after issuing SET ROLE upstream. Each
// probe must return the configured role; any mismatch means PgBouncer is
// silently swapping backends between queries (non-session pool mode) and the
// proxy refuses to enter the relay loop.
//
// In session mode the role always sticks, so all probes pass. In transaction
// or statement mode the role may stick across some queries by chance but a
// single mismatch is conclusive. Five iterations balances startup-time cost
// against detection probability.
const probeIterations = 5

// runSession owns a single client connection from accept through close. It
// performs the proxy-side handshake under a deadline, opens an upstream
// connection through pgconn, injects SET ROLE and probes for session-pool
// behavior, hijacks the connection, then runs the bidirectional relay loop.
func runSession(ctx context.Context, clientConn net.Conn, policy *Policy, logger *slog.Logger) {
	defer clientConn.Close()

	_ = clientConn.SetDeadline(time.Now().Add(handshakeTimeout))

	backend := pgproto3.NewBackend(clientConn, clientConn)

	startup, err := receiveStartup(clientConn, backend)
	if err != nil {
		logger.Debug("postgres: startup failed", slog.String("error", err.Error()), slog.String("remote", clientConn.RemoteAddr().String()))
		return
	}
	if startup == nil {
		// CancelRequest was handled and the connection closed.
		return
	}

	if err := authenticateClient(backend, startup, policy); err != nil {
		logger.Info("postgres: client auth failed",
			slog.String("error", err.Error()),
			slog.String("remote", clientConn.RemoteAddr().String()),
		)
		return
	}

	upstream, err := dialUpstream(ctx, policy)
	if err != nil {
		writeFatal(backend, "08006", "upstream connection failed")
		logger.Error("postgres: upstream connect failed", slog.String("error", err.Error()))
		return
	}

	if err := setRoleAndProbe(ctx, upstream, policy); err != nil {
		writeFatal(backend, "08006", err.Error())
		logger.Error("postgres: set role / probe failed",
			slog.String("error", err.Error()),
			slog.String("remote", clientConn.RemoteAddr().String()),
		)
		_ = upstream.Close(ctx)
		return
	}

	hijacked, err := upstream.Hijack()
	if err != nil {
		writeFatal(backend, "08006", "upstream hijack failed")
		logger.Error("postgres: upstream hijack failed", slog.String("error", err.Error()))
		return
	}
	defer hijacked.Conn.Close()

	if err := completeClientHandshake(backend, hijacked); err != nil {
		logger.Error("postgres: client handshake completion failed", slog.String("error", err.Error()))
		return
	}

	// Handshake complete; clear the deadline so long-running queries aren't
	// truncated by it. The relay loop drives I/O end-to-end from here.
	_ = clientConn.SetDeadline(time.Time{})

	relay := newRelay(clientConn, hijacked.Conn, backend, hijacked.Frontend, policy, logger)
	relay.run()
}

// receiveStartup handles the optional SSLRequest / GSSEncRequest preludes and
// returns the StartupMessage that follows. Returns (nil, nil) when the client
// sent a CancelRequest (handled by closing the connection) since the proxy
// does not support cancel forwarding.
func receiveStartup(rawConn net.Conn, backend *pgproto3.Backend) (*pgproto3.StartupMessage, error) {
	for attempt := 0; attempt < 3; attempt++ {
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, fmt.Errorf("receiving startup message: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.StartupMessage:
			return m, nil
		case *pgproto3.SSLRequest:
			// Client TLS not terminated. Reply 'N' and let the client reissue
			// an unencrypted StartupMessage.
			if _, err := rawConn.Write([]byte{'N'}); err != nil {
				return nil, fmt.Errorf("writing SSL refusal: %w", err)
			}
		case *pgproto3.GSSEncRequest:
			if _, err := rawConn.Write([]byte{'N'}); err != nil {
				return nil, fmt.Errorf("writing GSS refusal: %w", err)
			}
		case *pgproto3.CancelRequest:
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected startup message type %T", msg)
		}
	}
	return nil, errors.New("startup message preceded by too many SSL/GSS requests")
}

// dialUpstream opens an authenticated PgConn to the upstream database using
// the credentials in policy.
func dialUpstream(ctx context.Context, policy *Policy) (*pgconn.PgConn, error) {
	connString := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		policy.UpstreamHost(),
		policy.UpstreamPort(),
		policy.UpstreamUser(),
		policy.UpstreamPassword(),
		policy.UpstreamDatabase(),
		policy.UpstreamSSLMode(),
	)
	cfg, err := pgconn.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream config: %w", err)
	}
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting upstream: %w", err)
	}
	return conn, nil
}

// setRoleAndProbe issues `SET ROLE "<role>"` on the upstream session and then
// runs probeIterations separate autocommit `SELECT current_role` queries to
// verify the role persists. Any probe returning a different role means the
// upstream is rebinding backends between queries (PgBouncer in transaction or
// statement pool mode), which silently nullifies the policy. Returns an error
// in that case so the caller fails the client connection cleanly.
func setRoleAndProbe(ctx context.Context, conn *pgconn.PgConn, policy *Policy) error {
	setSQL := "SET ROLE " + QuoteIdent(policy.Role())
	if _, err := conn.Exec(ctx, setSQL).ReadAll(); err != nil {
		return fmt.Errorf("upstream rejected SET ROLE %s: %w", QuoteIdent(policy.Role()), err)
	}

	for i := 0; i < probeIterations; i++ {
		results, err := conn.Exec(ctx, "SELECT current_role").ReadAll()
		if err != nil {
			return fmt.Errorf("probe SELECT current_role failed: %w", err)
		}
		if len(results) != 1 || len(results[0].Rows) != 1 || len(results[0].Rows[0]) != 1 {
			return fmt.Errorf("probe SELECT current_role returned unexpected shape (got %d results)", len(results))
		}
		got := string(results[0].Rows[0][0])
		if got != policy.Role() {
			return fmt.Errorf("role did not persist between queries (saw %q, want %q) — upstream looks like PgBouncer in non-session pool mode; iron-proxy requires session pooling", got, policy.Role())
		}
	}
	return nil
}

// completeClientHandshake finishes the client-facing handshake by sending
// AuthenticationOk + ParameterStatus + BackendKeyData + ReadyForQuery. The
// ParameterStatus values are taken from the upstream's hijacked state so the
// client sees a coherent view of the server's runtime parameters.
//
// BackendKeyData is fabricated: the proxy does not support CancelRequest
// forwarding and must not leak the upstream's real key.
func completeClientHandshake(backend *pgproto3.Backend, hj *pgconn.HijackedConn) error {
	pid, secret, err := randomBackendKey()
	if err != nil {
		return fmt.Errorf("generating synthetic backend key: %w", err)
	}

	backend.Send(&pgproto3.AuthenticationOk{})
	for name, value := range hj.ParameterStatuses {
		backend.Send(&pgproto3.ParameterStatus{Name: name, Value: value})
	}
	backend.Send(&pgproto3.BackendKeyData{ProcessID: pid, SecretKey: secret})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	return backend.Flush()
}

// relay drives the bidirectional message pump between client and upstream
// after the role has been set on the upstream session.
//
// Two goroutines do socket I/O: c2s reads client messages and rejects
// role-changing or multi-statement queries before forwarding everything else;
// s2c is a pure passthrough.
//
// Writes to the client serialize through clientWriteMu since both goroutines
// may write — c2s when synthesizing a reject, s2c when forwarding the normal
// upstream reply stream.
type relay struct {
	clientConn   net.Conn
	upstreamConn net.Conn

	backend  *pgproto3.Backend
	frontend *pgproto3.Frontend

	policy *Policy
	logger *slog.Logger

	clientWriteMu sync.Mutex

	// skipExtended, when true, drops client Bind/Describe/Execute/Close
	// messages until a Sync is observed. Set when a Parse is rejected: per the
	// PostgreSQL Extended Query protocol, all messages between an error and a
	// Sync are ignored by the server. We mirror that so the proxy doesn't
	// forward orphaned messages upstream after our synthetic ErrorResponse.
	//
	// Read and written only by the c2s goroutine.
	skipExtended bool
}

func newRelay(clientConn, upstreamConn net.Conn, backend *pgproto3.Backend, frontend *pgproto3.Frontend, policy *Policy, logger *slog.Logger) *relay {
	return &relay{
		clientConn:   clientConn,
		upstreamConn: upstreamConn,
		backend:      backend,
		frontend:     frontend,
		policy:       policy,
		logger:       logger,
	}
}

func (r *relay) run() {
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		r.clientToServer()
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		r.serverToClient()
	}()

	<-done
	// Closing the underlying conns interrupts the other goroutine's blocking
	// read and lets it exit.
	_ = r.clientConn.Close()
	_ = r.upstreamConn.Close()
	<-done
}

// clientToServer reads frontend messages from the client and forwards them
// upstream, rejecting only role-changing statements and multi-statement
// Simple Queries.
func (r *relay) clientToServer() {
	for {
		msg, err := r.backend.Receive()
		if err != nil {
			if !isClosedConnErr(err) {
				r.logger.Debug("postgres: client read error", slog.String("error", err.Error()))
			}
			return
		}

		switch m := msg.(type) {
		case *pgproto3.Terminate:
			r.frontend.Send(m)
			_ = r.frontend.Flush()
			return

		case *pgproto3.Query:
			if r.skipExtended {
				// Unexpected mid-batch; treat the Simple Query as a fresh statement.
				r.skipExtended = false
			}
			if allowed, reason := ClassifyClientStatement(m.String); !allowed {
				r.writeReject(reason, true)
				continue
			}
			r.frontend.Send(m)
			if err := r.frontend.Flush(); err != nil {
				return
			}

		case *pgproto3.Parse:
			if allowed, reason := ClassifyClientStatement(m.Query); !allowed {
				r.writeReject(reason, false)
				r.skipExtended = true
				continue
			}
			r.frontend.Send(m)
			if err := r.frontend.Flush(); err != nil {
				return
			}

		case *pgproto3.Sync:
			if r.skipExtended {
				// We rejected an earlier Parse in this extended-query batch.
				// Synthesize a ReadyForQuery for the client and consume the
				// Sync without forwarding upstream.
				r.skipExtended = false
				r.writeClient(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				continue
			}
			r.frontend.Send(m)
			if err := r.frontend.Flush(); err != nil {
				return
			}

		default:
			if r.skipExtended {
				continue
			}
			r.frontend.Send(msg)
			if err := r.frontend.Flush(); err != nil {
				return
			}
		}
	}
}

// writeReject writes a synthetic ErrorResponse to the client. When
// withReadyForQuery is true (the Simple Query case) it also writes a
// ReadyForQuery so the client knows the proxy is again ready; the Extended
// Query case omits it because the client must drive to a Sync first.
func (r *relay) writeReject(reason RejectReason, withReadyForQuery bool) {
	r.clientWriteMu.Lock()
	defer r.clientWriteMu.Unlock()

	r.backend.Send(rejectError(reason))
	if withReadyForQuery {
		r.backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	}
	_ = r.backend.Flush()
}

// writeClient writes one or more BackendMessages to the client under the
// shared write mutex.
func (r *relay) writeClient(msgs ...pgproto3.BackendMessage) {
	r.clientWriteMu.Lock()
	defer r.clientWriteMu.Unlock()
	for _, m := range msgs {
		r.backend.Send(m)
	}
	_ = r.backend.Flush()
}

// rejectError builds the ErrorResponse synthesized for a policy denial.
func rejectError(reason RejectReason) *pgproto3.ErrorResponse {
	switch reason {
	case RejectMultiStatement:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "42601",
			Message:  "blocked by iron-proxy policy: multi-statement queries not permitted",
		}
	case RejectDoBlock:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "0A000",
			Message:  "blocked by iron-proxy policy: DO blocks are not supported (their plpgsql body cannot be inspected for embedded role changes)",
		}
	case RejectClientRoleChange:
		fallthrough
	default:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "42501",
			Message:  "blocked by iron-proxy policy: role is managed by the proxy; clients may not issue SET ROLE / SET SESSION AUTHORIZATION / RESET ROLE / set_config('role',...) / set_config('session_authorization',...)",
		}
	}
}

// serverToClient reads backend messages from the upstream and forwards them
// to the client unchanged.
func (r *relay) serverToClient() {
	for {
		msg, err := r.frontend.Receive()
		if err != nil {
			if !isClosedConnErr(err) {
				r.logger.Debug("postgres: upstream read error", slog.String("error", err.Error()))
			}
			return
		}
		r.writeClient(msg)
	}
}

func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}
