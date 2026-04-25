# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP021 (pyupgrade): replace universal newlines
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up021

import rego.v1

metadata := {
	"id": "RUFF-UP021",
	"name": "replace universal newlines",
	"description": "`universal_newlines` is deprecated, use `text`",
	"help_uri": "https://docs.astral.sh/ruff/rules/replace-universal-newlines/",
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
	"ruff_code": "UP021",
	"ruff_linter": "pyupgrade",
	"ruff_name": "replace-universal-newlines",
	"ruff_since": "v0.0.196",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bunicode_literals\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Replace unicode_literals import with u-strings",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
