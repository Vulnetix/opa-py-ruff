# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB110 (refurb): if exp instead of or operator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb110

import rego.v1

metadata := {
	"id": "RUFF-FURB110",
	"name": "if exp instead of or operator",
	"description": "Replace ternary `if` expression with `or` operator",
	"help_uri": "https://docs.astral.sh/ruff/rules/if-exp-instead-of-or-operator/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "refurb", "furb"],
	"ruff_code": "FURB110",
	"ruff_linter": "refurb",
	"ruff_name": "if-exp-instead-of-or-operator",
	"ruff_since": "0.15.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`x\s+if\s+x\s+else\s+y|a\s+or\s+b\s+if\s+not\s+a`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use x or y instead of x if x else y",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
