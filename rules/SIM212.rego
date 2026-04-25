# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM212 (flake8-simplify): if expr with twisted arms
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim212

import rego.v1

metadata := {
	"id": "RUFF-SIM212",
	"name": "if expr with twisted arms",
	"description": "Use `<value> if <value> else <value>` instead of `<value> if not <value> else <value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/if-expr-with-twisted-arms/",
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
	"ruff_code": "SIM212",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "if-expr-with-twisted-arms",
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
	regex.match(`\w+\s+if\s+not\s+\w+\s+else\s+\w+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use x if y else z — rewrite negation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
