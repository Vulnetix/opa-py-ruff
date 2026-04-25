# SPDX-License-Identifier: Apache-2.0
# Ruff rule EXE001 (flake8-executable): shebang not executable
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_exe001

import rego.v1

metadata := {
	"id": "RUFF-EXE001",
	"name": "shebang not executable",
	"description": "Shebang is present but file is not executable",
	"help_uri": "https://docs.astral.sh/ruff/rules/shebang-not-executable/",
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
	"ruff_code": "EXE001",
	"ruff_linter": "flake8-executable",
	"ruff_name": "shebang-not-executable",
	"ruff_since": "v0.0.233",
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
		"message": "Shebang is present but file is not executable",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
