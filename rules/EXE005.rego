# SPDX-License-Identifier: Apache-2.0
# Ruff rule EXE005 (flake8-executable): shebang not first line
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_exe005

import rego.v1

metadata := {
	"id": "RUFF-EXE005",
	"name": "shebang not first line",
	"description": "Shebang should be at the beginning of the file",
	"help_uri": "https://docs.astral.sh/ruff/rules/shebang-not-first-line/",
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
	"ruff_code": "EXE005",
	"ruff_linter": "flake8-executable",
	"ruff_name": "shebang-not-first-line",
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
	regex.match(`^#!/`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Shebang is not the first line",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
