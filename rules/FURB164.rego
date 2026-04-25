# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB164 (refurb): unnecessary from float
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb164

import rego.v1

metadata := {
	"id": "RUFF-FURB164",
	"name": "unnecessary from float",
	"description": "Verbose method `<value>` in `<value>` construction",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-from-float/",
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
	"ruff_code": "FURB164",
	"ruff_linter": "refurb",
	"ruff_name": "unnecessary-from-float",
	"ruff_since": "v0.3.5",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`random\.sample\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use random.choices() instead of random.sample()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
