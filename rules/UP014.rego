# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP014 (pyupgrade): convert named tuple functional to class
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up014

import rego.v1

metadata := {
	"id": "RUFF-UP014",
	"name": "convert named tuple functional to class",
	"description": "Convert `<value>` from `NamedTuple` functional to class syntax",
	"help_uri": "https://docs.astral.sh/ruff/rules/convert-named-tuple-functional-to-class/",
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
	"ruff_code": "UP014",
	"ruff_linter": "pyupgrade",
	"ruff_name": "convert-named-tuple-functional-to-class",
	"ruff_since": "v0.0.155",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bNamedTuple\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use class-based NamedTuple syntax",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
