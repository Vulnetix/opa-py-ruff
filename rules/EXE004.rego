# SPDX-License-Identifier: Apache-2.0
# Ruff rule EXE004 (flake8-executable): shebang leading whitespace
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_exe004

import rego.v1

metadata := {
	"id": "RUFF-EXE004",
	"name": "shebang leading whitespace",
	"description": "Avoid whitespace before shebang",
	"help_uri": "https://docs.astral.sh/ruff/rules/shebang-leading-whitespace/",
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
	"ruff_code": "EXE004",
	"ruff_linter": "flake8-executable",
	"ruff_name": "shebang-leading-whitespace",
	"ruff_since": "v0.0.229",
	"ruff_fix": "Always",
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
		"message": "Shebang on second line",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
