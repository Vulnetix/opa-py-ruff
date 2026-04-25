# SPDX-License-Identifier: Apache-2.0
# Ruff rule E722 (pycodestyle): bare except
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e722

import rego.v1

metadata := {
	"id": "RUFF-E722",
	"name": "bare except",
	"description": "Do not use bare `except`",
	"help_uri": "https://docs.astral.sh/ruff/rules/bare-except/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "e"],
	"ruff_code": "E722",
	"ruff_linter": "pycodestyle",
	"ruff_name": "bare-except",
	"ruff_since": "v0.0.36",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bexcept\s*:`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Bare `except` catches all exceptions including SystemExit",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
