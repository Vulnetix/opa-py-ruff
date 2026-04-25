# SPDX-License-Identifier: Apache-2.0
# Ruff rule TC001 (flake8-type-checking): typing only first party import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_tc001

import rego.v1

metadata := {
	"id": "RUFF-TC001",
	"name": "typing only first party import",
	"description": "Move application import `{}` into a type-checking block",
	"help_uri": "https://docs.astral.sh/ruff/rules/typing-only-first-party-import/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-type-checking", "tc"],
	"ruff_code": "TC001",
	"ruff_linter": "flake8-type-checking",
	"ruff_name": "typing-only-first-party-import",
	"ruff_since": "0.8.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^from\s+typing\s+import|^import\s+typing\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Move application import to TYPE_CHECKING block",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
