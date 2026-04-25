# SPDX-License-Identifier: Apache-2.0
# Ruff rule B021 (flake8-bugbear): f string docstring
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b021

import rego.v1

metadata := {
	"id": "RUFF-B021",
	"name": "f string docstring",
	"description": "f-string used as docstring. Python will interpret this as a joined string, rather than a docstring.",
	"help_uri": "https://docs.astral.sh/ruff/rules/f-string-docstring/",
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
	"ruff_code": "B021",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "f-string-docstring",
	"ruff_since": "v0.0.116",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`def\s+\w+\s*\(.*\)\s*->.*:\s*\n\s*"""[^"]*{.*}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "f-string in docstring",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
