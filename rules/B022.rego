# SPDX-License-Identifier: Apache-2.0
# Ruff rule B022 (flake8-bugbear): useless contextlib suppress
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b022

import rego.v1

metadata := {
	"id": "RUFF-B022",
	"name": "useless contextlib suppress",
	"description": "No arguments passed to `contextlib.suppress`. No exceptions will be suppressed and therefore this context manager is redundant",
	"help_uri": "https://docs.astral.sh/ruff/rules/useless-contextlib-suppress/",
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
	"ruff_code": "B022",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "useless-contextlib-suppress",
	"ruff_since": "v0.0.118",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`contextlib\.suppress\s*\(\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "contextlib.suppress() with no arguments",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
