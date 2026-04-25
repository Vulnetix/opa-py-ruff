# SPDX-License-Identifier: Apache-2.0
# Ruff rule B030 (flake8-bugbear): except with non exception classes
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b030

import rego.v1

metadata := {
	"id": "RUFF-B030",
	"name": "except with non exception classes",
	"description": "`except*` handlers should only be exception classes or tuples of exception classes",
	"help_uri": "https://docs.astral.sh/ruff/rules/except-with-non-exception-classes/",
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
	"ruff_code": "B030",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "except-with-non-exception-classes",
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
	regex.match(`except\s*\*`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Exception group syntax (verify Python 3.11+)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
