# SPDX-License-Identifier: Apache-2.0
# Ruff rule PGH003 (pygrep-hooks): blanket type ignore
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pgh003

import rego.v1

metadata := {
	"id": "RUFF-PGH003",
	"name": "blanket type ignore",
	"description": "Use specific rule codes when ignoring type issues",
	"help_uri": "https://docs.astral.sh/ruff/rules/blanket-type-ignore/",
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
	"ruff_code": "PGH003",
	"ruff_linter": "pygrep-hooks",
	"ruff_name": "blanket-type-ignore",
	"ruff_since": "v0.0.187",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`#\s*type:\s*ignore`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use specific rule codes in type ignore comments",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
