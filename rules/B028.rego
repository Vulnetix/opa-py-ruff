# SPDX-License-Identifier: Apache-2.0
# Ruff rule B028 (flake8-bugbear): no explicit stacklevel
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b028

import rego.v1

metadata := {
	"id": "RUFF-B028",
	"name": "no explicit stacklevel",
	"description": "No explicit `stacklevel` keyword argument found",
	"help_uri": "https://docs.astral.sh/ruff/rules/no-explicit-stacklevel/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B028",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "no-explicit-stacklevel",
	"ruff_since": "v0.0.257",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bwarnings\.warn\s*\(`, line)
	not regex.match(`.*stacklevel`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "warnings.warn() without stacklevel",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
