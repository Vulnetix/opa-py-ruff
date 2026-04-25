# SPDX-License-Identifier: Apache-2.0
# Ruff rule B013 (flake8-bugbear): redundant tuple in exception handler
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b013

import rego.v1

metadata := {
	"id": "RUFF-B013",
	"name": "redundant tuple in exception handler",
	"description": "A length-one tuple literal is redundant in exception handlers",
	"help_uri": "https://docs.astral.sh/ruff/rules/redundant-tuple-in-exception-handler/",
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
	"ruff_code": "B013",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "redundant-tuple-in-exception-handler",
	"ruff_since": "v0.0.89",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`except\s*\(\s*\w+\s*\)\s*:`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Redundant tuple in exception handler",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
