# SPDX-License-Identifier: Apache-2.0
# Ruff rule F401 (Pyflakes): unused import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f401

import rego.v1

metadata := {
	"id": "RUFF-F401",
	"name": "unused import",
	"description": "`<value>` imported but unused; consider using `importlib.util.find_spec` to test for availability",
	"help_uri": "https://docs.astral.sh/ruff/rules/unused-import/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyflakes", "f"],
	"ruff_code": "F401",
	"ruff_linter": "Pyflakes",
	"ruff_name": "unused-import",
	"ruff_since": "v0.0.18",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^(import |from .+ import )`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Module imported but unused",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
