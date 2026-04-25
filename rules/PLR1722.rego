# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR1722 (Pylint): sys exit alias
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr1722

import rego.v1

metadata := {
	"id": "RUFF-PLR1722",
	"name": "sys exit alias",
	"description": "Use `sys.exit()` instead of `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/sys-exit-alias/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plr"],
	"ruff_code": "PLR1722",
	"ruff_linter": "Pylint",
	"ruff_name": "sys-exit-alias",
	"ruff_since": "v0.0.156",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bsys\.exit\s*\(\s*0\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use sys.exit() without argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
