# SPDX-License-Identifier: Apache-2.0
# Ruff rule F811 (Pyflakes): redefined while unused
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f811

import rego.v1

metadata := {
	"id": "RUFF-F811",
	"name": "redefined while unused",
	"description": "Redefinition of unused `<value>` from <value>",
	"help_uri": "https://docs.astral.sh/ruff/rules/redefined-while-unused/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyflakes", "f"],
	"ruff_code": "F811",
	"ruff_linter": "Pyflakes",
	"ruff_name": "redefined-while-unused",
	"ruff_since": "v0.0.171",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^(import |from .+ import |def |class )`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Redefinition of unused name",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
