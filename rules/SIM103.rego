# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM103 (flake8-simplify): needless bool
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim103

import rego.v1

metadata := {
	"id": "RUFF-SIM103",
	"name": "needless bool",
	"description": "Return the condition `<value>` directly",
	"help_uri": "https://docs.astral.sh/ruff/rules/needless-bool/",
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
	"ruff_code": "SIM103",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "needless-bool",
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
	regex.match(`if\s+.+:\s*\n\s+return\s+True\s*\n\s*(else:)?\s*\n?\s*return\s+False`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Return condition directly",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
