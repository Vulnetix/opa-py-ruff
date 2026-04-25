# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0101 (Pylint): return in init
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0101

import rego.v1

metadata := {
	"id": "RUFF-PLE0101",
	"name": "return in init",
	"description": "Explicit return in `__init__`",
	"help_uri": "https://docs.astral.sh/ruff/rules/return-in-init/",
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
	"ruff_code": "PLE0101",
	"ruff_linter": "Pylint",
	"ruff_name": "return-in-init",
	"ruff_since": "v0.0.248",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`def\s+__init__\s*\([^)]*\).*return\s+\w+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "__init__ with return value",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
