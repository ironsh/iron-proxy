package postgres

// RejectReason categorizes why the proxy is refusing a client message in the
// relay loop. Surfaced as the synthetic ErrorResponse's Message and on
// structured logs.
type RejectReason int

const (
	// RejectClientRoleChange — the client tried to issue
	// SET ROLE / RESET ROLE / SET SESSION AUTHORIZATION / RESET SESSION AUTHORIZATION.
	// The proxy sets the role at session start and forbids overrides.
	RejectClientRoleChange RejectReason = iota + 1
	// RejectDoBlock — the client sent a DO $$ ... $$ anonymous code block.
	// The plpgsql body is opaque to our SQL-level AST walker; rejecting
	// avoids the risk of an embedded role change.
	RejectDoBlock
)

// ClassifyClientStatement inspects sql and returns whether the relay should
// reject it before forwarding upstream. (reason == 0) means "allow".
//
// Multi-statement Simple Queries are allowed when every statement passes the
// role policy; Classify rejects the batch if any statement mutates the role or
// is a DO block.
//
// Used for both Simple Query bodies and the SQL string carried by Extended
// Query Parse messages.
func ClassifyClientStatement(sql string) (allowed bool, reason RejectReason) {
	op := Classify(sql)
	switch op.Kind {
	case OpSetRole, OpSetSessionAuthorization, OpResetRole, OpResetSessionAuthorization:
		return false, RejectClientRoleChange
	case OpDoBlock:
		// DO blocks contain opaque plpgsql we can't introspect from the SQL
		// AST. Rather than risk an embedded role change slipping through,
		// we reject them outright.
		return false, RejectDoBlock
	default:
		return true, 0
	}
}
