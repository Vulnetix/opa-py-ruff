# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP025 (pyupgrade): unicode kind prefix
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up025

import rego.v1

metadata := {
	"id": "RUFF-UP025",
	"name": "unicode kind prefix",
	"description": "Remove unicode literals from strings",
	"help_uri": "https://docs.astral.sh/ruff/rules/unicode-kind-prefix/",
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
	"ruff_code": "UP025",
	"ruff_linter": "pyupgrade",
	"ruff_name": "unicode-kind-prefix",
	"ruff_since": "v0.0.201",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bu["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Remove unicode literals",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
