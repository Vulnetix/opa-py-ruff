# SPDX-License-Identifier: Apache-2.0
# Ruff rule RET507 (flake8-return): superfluous else continue
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ret507

import rego.v1

metadata := {
	"id": "RUFF-RET507",
	"name": "superfluous else continue",
	"description": "Unnecessary `<value>` after `continue` statement",
	"help_uri": "https://docs.astral.sh/ruff/rules/superfluous-else-continue/",
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
	"ruff_code": "RET507",
	"ruff_linter": "flake8-return",
	"ruff_name": "superfluous-else-continue",
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
	regex.match(`if\s+.+:\s*\n\s+continue.*\n\s*else:`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Superfluous else after continue",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
