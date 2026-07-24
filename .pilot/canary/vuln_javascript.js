// CANARY FIXTURE — DELIBERATELY VULNERABLE. Never real code. See .pilot/canary/README.md.
//
// Expected: pr-blocking rule `code-string-concat`
// (pr-blocking/javascript/lang/security/audit/code-string-concat.yaml)
// CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
// OWASP A03:2021 - Injection
//
// Taint-mode rule: an Express request field (req.query/req.body/req.params/
// req.cookies/req.headers) flowing, unsanitized, into eval().

const express = require("express");
const app = express();

app.get("/run", function (req, res) {
  const cmd = req.query.cmd;
  eval(cmd);
  res.send("done");
});

module.exports = app;
