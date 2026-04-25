# SPDX-License-Identifier: Apache-2.0
# Ruff rule B031 (flake8-bugbear): reuse of groupby generator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b031

import rego.v1

metadata := {
	"id": "RUFF-B031",
	"name": "reuse of groupby generator",
	"description": "Using the generator returned from `itertools.groupby()` more than once will do nothing on the second usage",
	"help_uri": "https://docs.astral.sh/ruff/rules/reuse-of-groupby-generator/",
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
	"ruff_code": "B031",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "reuse-of-groupby-generator",
	"ruff_since": "v0.0.260",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`for\s+\w+\s+in\s+itertools\.groupby\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "itertools.groupby() result is iterated multiple times",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
