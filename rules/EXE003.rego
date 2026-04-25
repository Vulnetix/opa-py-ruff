# SPDX-License-Identifier: Apache-2.0
# Ruff rule EXE003 (flake8-executable): shebang missing python
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_exe003

import rego.v1

metadata := {
	"id": "RUFF-EXE003",
	"name": "shebang missing python",
	"description": "Shebang should contain `python`, `pytest`, or `uv run`",
	"help_uri": "https://docs.astral.sh/ruff/rules/shebang-missing-python/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-executable", "exe"],
	"ruff_code": "EXE003",
	"ruff_linter": "flake8-executable",
	"ruff_name": "shebang-missing-python",
	"ruff_since": "v0.0.229",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^#!/usr/bin/env\s+python`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Shebang should contain python",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
