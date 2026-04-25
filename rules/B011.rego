# SPDX-License-Identifier: Apache-2.0
# Ruff rule B011 (flake8-bugbear): assert false
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b011

import rego.v1

metadata := {
	"id": "RUFF-B011",
	"name": "assert false",
	"description": "Do not `assert False` (`python -O` removes these calls), raise `AssertionError()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/assert-false/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B011",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "assert-false",
	"ruff_since": "v0.0.67",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bassert\s+False\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Do not assert False — raise AssertionError() instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
