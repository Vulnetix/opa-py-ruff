# SPDX-License-Identifier: Apache-2.0
# Ruff rule PTH124 (flake8-use-pathlib): py path
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pth124

import rego.v1

metadata := {
	"id": "RUFF-PTH124",
	"name": "py path",
	"description": "`py.path` is in maintenance mode, use `pathlib` instead",
	"help_uri": "https://docs.astral.sh/ruff/rules/py-path/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-use-pathlib", "pth"],
	"ruff_code": "PTH124",
	"ruff_linter": "flake8-use-pathlib",
	"ruff_name": "py-path",
	"ruff_since": "v0.0.231",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bpy\.path\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use pathlib.Path instead of py.path",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
