# SPDX-License-Identifier: Apache-2.0
# Ruff rule EXE002 (flake8-executable): shebang missing executable file
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_exe002

import rego.v1

metadata := {
	"id": "RUFF-EXE002",
	"name": "shebang missing executable file",
	"description": "The file is executable but no shebang is present",
	"help_uri": "https://docs.astral.sh/ruff/rules/shebang-missing-executable-file/",
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
	"ruff_code": "EXE002",
	"ruff_linter": "flake8-executable",
	"ruff_name": "shebang-missing-executable-file",
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
		"message": "The file is executable but no shebee is present",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
