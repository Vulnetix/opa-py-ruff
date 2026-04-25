# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI052 (flake8-pyi): unannotated assignment in stub
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi052

import rego.v1

metadata := {
	"id": "RUFF-PYI052",
	"name": "unannotated assignment in stub",
	"description": "Need type annotation for `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/unannotated-assignment-in-stub/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pyi", "pyi"],
	"ruff_code": "PYI052",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "unannotated-assignment-in-stub",
	"ruff_since": "v0.0.269",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`Final\[int\]\s*=\s*\d+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Need type comment for final",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
