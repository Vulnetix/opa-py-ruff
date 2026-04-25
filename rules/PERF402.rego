# SPDX-License-Identifier: Apache-2.0
# Ruff rule PERF402 (Perflint): manual list copy
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_perf402

import rego.v1

metadata := {
	"id": "RUFF-PERF402",
	"name": "manual list copy",
	"description": "Use `list` or `list.copy` to create a copy of a list",
	"help_uri": "https://docs.astral.sh/ruff/rules/manual-list-copy/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "perflint", "perf"],
	"ruff_code": "PERF402",
	"ruff_linter": "Perflint",
	"ruff_name": "manual-list-copy",
	"ruff_since": "v0.0.276",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`for\s+\w+\s+in\s+\w+:\s*\n\s+\w+\.append\s*\(\1\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use list or list.copy() to create a copy of a list",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
