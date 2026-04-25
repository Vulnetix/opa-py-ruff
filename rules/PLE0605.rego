# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0605 (Pylint): invalid all format
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0605

import rego.v1

metadata := {
	"id": "RUFF-PLE0605",
	"name": "invalid all format",
	"description": "Invalid format for `__all__`, must be `tuple` or `list`",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-all-format/",
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
	"ruff_code": "PLE0605",
	"ruff_linter": "Pylint",
	"ruff_name": "invalid-all-format",
	"ruff_since": "v0.0.237",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`__all__\s*\+=\s*\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Invalid format of __all__",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
