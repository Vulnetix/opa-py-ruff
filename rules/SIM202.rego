# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM202 (flake8-simplify): negate not equal op
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim202

import rego.v1

metadata := {
	"id": "RUFF-SIM202",
	"name": "negate not equal op",
	"description": "Use `<value> == <value>` instead of `not <value> != <value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/negate-not-equal-op/",
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
	"ruff_code": "SIM202",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "negate-not-equal-op",
	"ruff_since": "v0.0.213",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`not\s+\w+\s*!=\s*\w+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use == instead of not !=",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
