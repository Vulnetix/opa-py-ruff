# SPDX-License-Identifier: Apache-2.0
# Ruff rule RET506 (flake8-return): superfluous else raise
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ret506

import rego.v1

metadata := {
	"id": "RUFF-RET506",
	"name": "superfluous else raise",
	"description": "Unnecessary `<value>` after `raise` statement",
	"help_uri": "https://docs.astral.sh/ruff/rules/superfluous-else-raise/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-return", "ret"],
	"ruff_code": "RET506",
	"ruff_linter": "flake8-return",
	"ruff_name": "superfluous-else-raise",
	"ruff_since": "v0.0.154",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`if\s+.+:\s*\n\s+raise.*\n\s*else:`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Superfluous else after raise",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
