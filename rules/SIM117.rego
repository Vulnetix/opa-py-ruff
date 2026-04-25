# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM117 (flake8-simplify): multiple with statements
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim117

import rego.v1

metadata := {
	"id": "RUFF-SIM117",
	"name": "multiple with statements",
	"description": "Use a single `with` statement with multiple contexts instead of nested `with` statements",
	"help_uri": "https://docs.astral.sh/ruff/rules/multiple-with-statements/",
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
	"ruff_code": "SIM117",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "multiple-with-statements",
	"ruff_since": "v0.0.211",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`with\s+.+:\s*\n\s+with\s+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Merge nested with statements",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
