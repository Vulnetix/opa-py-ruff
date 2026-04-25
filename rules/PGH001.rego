# SPDX-License-Identifier: Apache-2.0
# Ruff rule PGH001 (pygrep-hooks): eval
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pgh001

import rego.v1

metadata := {
	"id": "RUFF-PGH001",
	"name": "eval",
	"description": "No builtin `eval()` allowed",
	"help_uri": "https://docs.astral.sh/ruff/rules/eval/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pygrep-hooks", "pgh"],
	"ruff_code": "PGH001",
	"ruff_linter": "pygrep-hooks",
	"ruff_name": "eval",
	"ruff_since": "v0.2.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\beval\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "No eval() allowed",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
