package postgres

import (
	"strings"

	// The wasilibs package is a pure-Go (wazero-based) drop-in for pg_query_go's
	// Parse function, sparing us from a CGO build dependency. AST node types
	// still come from the pganalyze package; wasilibs re-uses them.
	pgparse "github.com/wasilibs/go-pgquery"
	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/reflect/protoreflect"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Op classifies a Postgres query string for the role-policy relay.
//
// The classifier uses the actual PostgreSQL parser (via libpg_query) to walk
// the AST, which lets it catch indirect role-change attempts that a regex
// lexer would miss — e.g. `SELECT set_config('role', 'admin', false)`,
// `WITH x AS (SELECT pg_catalog.set_config('role', ...)) SELECT * FROM x`,
// or `PREPARE p AS SET ROLE admin`.
type Op struct {
	// Kind is the classified statement kind.
	Kind OpKind
}

// OpKind enumerates the statement classes the policy reasons about.
type OpKind int

const (
	// OpOther is any statement not matched by a more specific case.
	OpOther OpKind = iota
	// OpSetRole is `SET ROLE <ident>` or anything anywhere in the AST that
	// changes the `role` GUC — including SET LOCAL, SET SESSION,
	// and function-call bypasses like `set_config('role', ...)`.
	OpSetRole
	// OpSetSessionAuthorization is the equivalent for `session_authorization`.
	OpSetSessionAuthorization
	// OpResetRole is `RESET ROLE` or any equivalent reset of the role GUC.
	OpResetRole
	// OpResetSessionAuthorization is the same for session_authorization.
	OpResetSessionAuthorization
	// OpMulti indicates the input contains more than one top-level statement.
	// Rejected to keep the policy decidable.
	OpMulti
	// OpEmpty indicates a whitespace/comment-only input or no statements.
	OpEmpty
	// OpDoBlock is a DO $$ ... $$ block. The plpgsql body is opaque to our
	// AST walker (the SQL parser produces a single DoStmt with the body as a
	// string literal; analyzing plpgsql requires a separate parser), so we
	// reject DO blocks rather than risk missing an embedded role change.
	OpDoBlock
	// OpParseError indicates pg_query rejected the input. We forward to
	// upstream so Postgres produces the canonical syntax error; the proxy
	// doesn't try to second-guess.
	OpParseError
)

// GUC names whose mutation we treat as a role change for policy purposes.
// Case-insensitive comparison; Postgres treats GUC names case-insensitively.
var roleGUCs = map[string]OpKind{
	"role":                  OpSetRole,
	"session_authorization": OpSetSessionAuthorization,
}

// dangerous set_config / current_setting target GUCs. We don't reject reads
// (current_setting), only writes (set_config).
var roleGUCsForSetConfig = map[string]OpKind{
	"role":                  OpSetRole,
	"session_authorization": OpSetSessionAuthorization,
}

// classifyCache memoizes Classify results so repeated queries (the common
// case in ORM workloads where the same parameterized SQL fires hundreds of
// times per connection) don't re-parse on the hot path. Bounded so a
// pathological client sending unique SQL per query can't exhaust memory.
var classifyCache *lru.Cache[string, Op]

func init() {
	c, err := lru.New[string, Op](1024)
	if err != nil {
		// lru.New only errors on size <= 0; 1024 is fixed and safe.
		panic(err)
	}
	classifyCache = c
}

// Classify returns the Op describing sql.
func Classify(sql string) Op {
	if op, ok := classifyCache.Get(sql); ok {
		return op
	}
	op := classifyUncached(sql)
	classifyCache.Add(sql, op)
	return op
}

func classifyUncached(sql string) Op {
	if strings.TrimSpace(sql) == "" {
		return Op{Kind: OpEmpty}
	}

	result, err := pgparse.Parse(sql)
	if err != nil {
		return Op{Kind: OpParseError}
	}
	stmts := result.GetStmts()
	if len(stmts) == 0 {
		return Op{Kind: OpEmpty}
	}
	if len(stmts) > 1 {
		return Op{Kind: OpMulti}
	}

	root := stmts[0].GetStmt()
	if root == nil {
		return Op{Kind: OpEmpty}
	}

	// Top-level shape gives us a fast path for the common DDL/DML cases.
	switch root.Node.(type) {
	case *pg_query.Node_TransactionStmt:
		// BEGIN / COMMIT / ROLLBACK / SAVEPOINT etc. — no role mutation.
		return Op{Kind: OpOther}
	case *pg_query.Node_DoStmt:
		return Op{Kind: OpDoBlock}
	}

	// Generic scan: any role-affecting node anywhere in the tree triggers a
	// rejection. Covers SELECT set_config(...), PREPARE ... AS SET ROLE,
	// CTEs, subqueries, INSERT...SELECT, function arguments, etc.
	if kind := scanForRoleChange(root); kind != 0 {
		return Op{Kind: kind}
	}
	return Op{Kind: OpOther}
}

// scanForRoleChange walks the AST rooted at node and returns the OpKind of
// any role-affecting construct it finds. Returns 0 if none.
//
// The walk uses protoreflect for generic descent so we don't have to maintain
// a hand-rolled case statement for every Node subtype as Postgres adds
// syntax. Any nested *VariableSetStmt or *FuncCall to set_config is caught
// regardless of how it's wrapped.
func scanForRoleChange(node *pg_query.Node) OpKind {
	var found OpKind
	walkProto(node.ProtoReflect(), func(m protoreflect.Message) bool {
		msg := m.Interface()
		switch n := msg.(type) {
		case *pg_query.VariableSetStmt:
			if kind, ok := roleGUCs[strings.ToLower(n.GetName())]; ok {
				switch n.GetKind() {
				case pg_query.VariableSetKind_VAR_RESET, pg_query.VariableSetKind_VAR_RESET_ALL:
					if kind == OpSetRole {
						found = OpResetRole
					} else {
						found = OpResetSessionAuthorization
					}
				default:
					found = kind
				}
				return false
			}
		case *pg_query.VariableShowStmt:
			// SHOW is read-only; allow.
		case *pg_query.FuncCall:
			if kind := classifyFuncCall(n); kind != 0 {
				found = kind
				return false
			}
		}
		return true
	})
	return found
}

// classifyFuncCall returns a role-change OpKind if fc is a call to
// set_config (or pg_catalog.set_config) whose first argument is a string
// literal naming a role-mutating GUC. Returns 0 otherwise.
func classifyFuncCall(fc *pg_query.FuncCall) OpKind {
	names := fc.GetFuncname()
	if len(names) == 0 {
		return 0
	}
	// Funcname is a list of String nodes: ["set_config"] for unqualified
	// or ["pg_catalog", "set_config"] for schema-qualified. We accept any
	// schema qualifier and trust that user-defined set_config functions
	// are also suspicious — better a rare false positive than a bypass.
	last := names[len(names)-1]
	lastStr, ok := last.Node.(*pg_query.Node_String_)
	if !ok {
		return 0
	}
	if !strings.EqualFold(lastStr.String_.GetSval(), "set_config") {
		return 0
	}
	args := fc.GetArgs()
	if len(args) < 1 {
		return 0
	}
	param, ok := stringConst(args[0])
	if !ok {
		return 0
	}
	kind, ok := roleGUCsForSetConfig[strings.ToLower(param)]
	if !ok {
		return 0
	}
	return kind
}

// stringConst returns the string value of node if it's an A_Const with a
// string value, else ("", false). set_config's first argument is the GUC
// name; we only flag calls where it's a literal we can read at parse time.
// `set_config(my_var, ...)` where my_var is a variable evaluates at run
// time and is invisible to us — accepted limitation.
func stringConst(node *pg_query.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	c, ok := node.Node.(*pg_query.Node_AConst)
	if !ok {
		return "", false
	}
	sval, ok := c.AConst.Val.(*pg_query.A_Const_Sval)
	if !ok {
		return "", false
	}
	return sval.Sval.GetSval(), true
}

// walkProto invokes visit on every message in the tree rooted at m, including
// m itself, descending through any singular message or list-of-message fields.
// Returning false from visit short-circuits the walk.
func walkProto(m protoreflect.Message, visit func(protoreflect.Message) bool) bool {
	if !visit(m) {
		return false
	}
	var stop bool
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind {
			return true
		}
		switch {
		case fd.IsList():
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				if !walkProto(list.Get(i).Message(), visit) {
					stop = true
					return false
				}
			}
		case fd.IsMap():
			// pg_query has no map-of-message fields; skip for simplicity.
		default:
			if !walkProto(v.Message(), visit) {
				stop = true
				return false
			}
		}
		return true
	})
	return !stop
}
