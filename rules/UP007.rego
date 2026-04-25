# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP007 (pyupgrade): non pep604 annotation union
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up007

import rego.v1

metadata := {
	"id": "RUFF-UP007",
	"name": "non pep604 annotation union",
	"description": "Use `X | Y` for type annotations",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-pep604-annotation-union/",
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
	"ruff_code": "UP007",
	"ruff_linter": "pyupgrade",
	"ruff_name": "non-pep604-annotation-union",
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
	regex.match(`Optional\[|Union\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use X | Y for union type annotations (Python 3.10+)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
