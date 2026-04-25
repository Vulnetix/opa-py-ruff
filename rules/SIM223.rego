# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM223 (flake8-simplify): expr and false
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim223

import rego.v1

metadata := {
	"id": "RUFF-SIM223",
	"name": "expr and false",
	"description": "Use `<value>` instead of `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/expr-and-false/",
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
	"ruff_code": "SIM223",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "expr-and-false",
	"ruff_since": "v0.0.208",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`not\s+\w+\s+and\s+not\s+\w+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use not (x or y) instead of not x and not y",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
