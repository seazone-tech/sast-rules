// CANARY FIXTURE — DELIBERATELY VULNERABLE. Never real code. See .pilot/canary/README.md.
//
// Expected: pr-blocking rule `tainted-sql-string`
// (pr-blocking/go/lang/security/injection/tainted-sql-string.yaml)
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
// ('SQL Injection'). OWASP A03:2021 - Injection.
//
// Taint-mode rule: an *http.Request field (FormValue) flowing, unsanitized,
// into a manually-concatenated SQL string passed to a query call.

package canary

import (
	"database/sql"
	"net/http"
)

func LookupUser(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	name := r.FormValue("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	return db.Query(query)
}
