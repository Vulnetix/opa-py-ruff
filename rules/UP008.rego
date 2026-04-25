# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP008 (pyupgrade): super call with parameters
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up008

import rego.v1

metadata := {
	"id": "RUFF-UP008",
	"name": "super call with parameters",
	"description": "Use `super()` instead of `super(__class__, self)`",
	"help_uri": "https://docs.astral.sh/ruff/rules/super-call-with-parameters/",
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
	"ruff_code": "UP008",
	"ruff_linter": "pyupgrade",
	"ruff_name": "super-call-with-parameters",
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
	regex.match(`\bsuper\s*\(\s*\w+\s*,\s*self\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use super() without arguments",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
