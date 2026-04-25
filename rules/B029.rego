# SPDX-License-Identifier: Apache-2.0
# Ruff rule B029 (flake8-bugbear): except with empty tuple
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b029

import rego.v1

metadata := {
	"id": "RUFF-B029",
	"name": "except with empty tuple",
	"description": "Using `except* ():` with an empty tuple does not catch anything; add exceptions to handle",
	"help_uri": "https://docs.astral.sh/ruff/rules/except-with-empty-tuple/",
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
	"ruff_code": "B029",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "except-with-empty-tuple",
	"ruff_since": "v0.0.250",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`except\s*\(\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Catch empty tuple of exceptions",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
