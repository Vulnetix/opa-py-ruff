# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0129 (Pylint): assert on string literal
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0129

import rego.v1

metadata := {
	"id": "RUFF-PLW0129",
	"name": "assert on string literal",
	"description": "Asserting on an empty string literal will never pass",
	"help_uri": "https://docs.astral.sh/ruff/rules/assert-on-string-literal/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plw"],
	"ruff_code": "PLW0129",
	"ruff_linter": "Pylint",
	"ruff_name": "assert-on-string-literal",
	"ruff_since": "v0.0.258",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`assert\s*\(.*,`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Assertion of a non-empty tuple",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
