# SPDX-License-Identifier: Apache-2.0
# Ruff rule LOG009 (flake8-logging): undocumented warn
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_log009

import rego.v1

metadata := {
	"id": "RUFF-LOG009",
	"name": "undocumented warn",
	"description": "Use of undocumented `logging.WARN` constant",
	"help_uri": "https://docs.astral.sh/ruff/rules/undocumented-warn/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-logging", "log"],
	"ruff_code": "LOG009",
	"ruff_linter": "flake8-logging",
	"ruff_name": "undocumented-warn",
	"ruff_since": "v0.2.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`logging\.WARN\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use of logging.WARN is deprecated",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
