# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP024 (pyupgrade): os error alias
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up024

import rego.v1

metadata := {
	"id": "RUFF-UP024",
	"name": "os error alias",
	"description": "Replace aliased errors with `OSError`",
	"help_uri": "https://docs.astral.sh/ruff/rules/os-error-alias/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP024",
	"ruff_linter": "pyupgrade",
	"ruff_name": "os-error-alias",
	"ruff_since": "v0.0.206",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bIOError\b|\bEnvironmentError\b|\bWindowsError\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use OSError instead of legacy aliases",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
