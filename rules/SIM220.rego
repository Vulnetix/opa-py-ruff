# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM220 (flake8-simplify): expr and not expr
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim220

import rego.v1

metadata := {
	"id": "RUFF-SIM220",
	"name": "expr and not expr",
	"description": "Use `False` instead of `<value> and not <value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/expr-and-not-expr/",
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
	"ruff_code": "SIM220",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "expr-and-not-expr",
	"ruff_since": "v0.0.211",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\w+\s+and\s+not\s+\w+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use x and not y",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
