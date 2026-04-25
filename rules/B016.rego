# SPDX-License-Identifier: Apache-2.0
# Ruff rule B016 (flake8-bugbear): raise literal
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b016

import rego.v1

metadata := {
	"id": "RUFF-B016",
	"name": "raise literal",
	"description": "Cannot raise a literal. Did you intend to return it or raise an Exception?",
	"help_uri": "https://docs.astral.sh/ruff/rules/raise-literal/",
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
	"ruff_code": "B016",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "raise-literal",
	"ruff_since": "v0.0.102",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`raise\s+(NotImplemented|BaseException)\s*\(\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Raise NotImplementedError instead of NotImplemented",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
