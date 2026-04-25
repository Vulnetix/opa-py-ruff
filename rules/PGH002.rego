# SPDX-License-Identifier: Apache-2.0
# Ruff rule PGH002 (pygrep-hooks): deprecated log warn
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pgh002

import rego.v1

metadata := {
	"id": "RUFF-PGH002",
	"name": "deprecated log warn",
	"description": "`warn` is deprecated in favor of `warning`",
	"help_uri": "https://docs.astral.sh/ruff/rules/deprecated-log-warn/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pygrep-hooks", "pgh"],
	"ruff_code": "PGH002",
	"ruff_linter": "pygrep-hooks",
	"ruff_name": "deprecated-log-warn",
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
	regex.match(`@deprecated\b|warnings\.warn.*DeprecationWarning`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Deprecated warnings",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
