# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB192 (refurb): sorted min max
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb192

import rego.v1

metadata := {
	"id": "RUFF-FURB192",
	"name": "sorted min max",
	"description": "Prefer `min` over `sorted()` to compute the minimum value in a sequence",
	"help_uri": "https://docs.astral.sh/ruff/rules/sorted-min-max/",
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
	"ruff_code": "FURB192",
	"ruff_linter": "refurb",
	"ruff_name": "sorted-min-max",
	"ruff_since": "v0.4.2",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`sorted\s*\(\s*\w+\s*\)\s*\[0\]|sorted\s*\(\s*\w+\s*,\s*reverse=True\s*\)\s*\[0\]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use min() or max() instead of sorted()[0]",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
