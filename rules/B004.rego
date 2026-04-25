# SPDX-License-Identifier: Apache-2.0
# Ruff rule B004 (flake8-bugbear): unreliable callable check
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b004

import rego.v1

metadata := {
	"id": "RUFF-B004",
	"name": "unreliable callable check",
	"description": "Using `hasattr(x, '__call__')` to test if x is callable is unreliable. Use `callable(x)` for consistent results.",
	"help_uri": "https://docs.astral.sh/ruff/rules/unreliable-callable-check/",
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
	"ruff_code": "B004",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "unreliable-callable-check",
	"ruff_since": "v0.0.106",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`__all__\s*\+=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Do not augment __all__ with +=",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
