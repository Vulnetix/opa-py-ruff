# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM211 (flake8-simplify): if expr with false true
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim211

import rego.v1

metadata := {
	"id": "RUFF-SIM211",
	"name": "if expr with false true",
	"description": "Use `not ...` instead of `False if ... else True`",
	"help_uri": "https://docs.astral.sh/ruff/rules/if-expr-with-false-true/",
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
	"ruff_code": "SIM211",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "if-expr-with-false-true",
	"ruff_since": "v0.0.214",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`False\s+if\s+.+\s+else\s+True`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use not expression instead of False if x else True",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
