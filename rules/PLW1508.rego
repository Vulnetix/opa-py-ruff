# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW1508 (Pylint): invalid envvar default
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw1508

import rego.v1

metadata := {
	"id": "RUFF-PLW1508",
	"name": "invalid envvar default",
	"description": "Invalid type for environment variable default; expected `str` or `None`",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-envvar-default/",
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
	"ruff_code": "PLW1508",
	"ruff_linter": "Pylint",
	"ruff_name": "invalid-envvar-default",
	"ruff_since": "v0.0.255",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`os\.getenv\s*\(\s*\w+\s*,\s*\d+\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "os.getenv() with non-None default of wrong type",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
