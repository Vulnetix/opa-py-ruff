# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM210 (flake8-simplify): if expr with true false
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim210

import rego.v1

metadata := {
	"id": "RUFF-SIM210",
	"name": "if expr with true false",
	"description": "Remove unnecessary `True if ... else False`",
	"help_uri": "https://docs.astral.sh/ruff/rules/if-expr-with-true-false/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-simplify", "sim"],
	"ruff_code": "SIM210",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "if-expr-with-true-false",
	"ruff_since": "v0.0.214",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`True\s+if\s+.+\s+else\s+False`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use bool() or direct expression instead of x if x else False",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
