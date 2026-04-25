# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI056 (flake8-pyi): unsupported method call on all
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi056

import rego.v1

metadata := {
	"id": "RUFF-PYI056",
	"name": "unsupported method call on all",
	"description": "Calling `.<value>()` on `__all__` may not be supported by all type checkers (use `+=` instead)",
	"help_uri": "https://docs.astral.sh/ruff/rules/unsupported-method-call-on-all/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pyi", "pyi"],
	"ruff_code": "PYI056",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "unsupported-method-call-on-all",
	"ruff_since": "v0.0.281",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.__all__\s*\+=|\.__all__\s*\|=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "__all__ with augmented assignment in stub",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
