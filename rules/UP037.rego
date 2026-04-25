# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP037 (pyupgrade): quoted annotation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up037

import rego.v1

metadata := {
	"id": "RUFF-UP037",
	"name": "quoted annotation",
	"description": "Remove quotes from type annotation",
	"help_uri": "https://docs.astral.sh/ruff/rules/quoted-annotation/",
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
	"ruff_code": "UP037",
	"ruff_linter": "pyupgrade",
	"ruff_name": "quoted-annotation",
	"ruff_since": "v0.0.242",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`from\s+__future__\s+import\s+annotations`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Remove __future__ annotations import",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
