# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB136 (refurb): if expr min max
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb136

import rego.v1

metadata := {
	"id": "RUFF-FURB136",
	"name": "if expr min max",
	"description": "Replace `if` expression with `<value>` call",
	"help_uri": "https://docs.astral.sh/ruff/rules/if-expr-min-max/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "refurb", "furb"],
	"ruff_code": "FURB136",
	"ruff_linter": "refurb",
	"ruff_name": "if-expr-min-max",
	"ruff_since": "0.5.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`True\s+if\s+.+\s+else\s+False`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use comparison expression directly",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
