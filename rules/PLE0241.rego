# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0241 (Pylint): duplicate bases
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0241

import rego.v1

metadata := {
	"id": "RUFF-PLE0241",
	"name": "duplicate bases",
	"description": "Duplicate base `<value>` for class `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/duplicate-bases/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "ple"],
	"ruff_code": "PLE0241",
	"ruff_linter": "Pylint",
	"ruff_name": "duplicate-bases",
	"ruff_since": "v0.0.269",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`class\s+\w+.*:\s*$\n.*pass.*\n\s*,`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Duplicate base class",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
