# SPDX-License-Identifier: Apache-2.0
# Ruff rule N811 (pep8-naming): constant imported as non constant
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_n811

import rego.v1

metadata := {
	"id": "RUFF-N811",
	"name": "constant imported as non constant",
	"description": "Constant `<value>` imported as non-constant `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/constant-imported-as-non-constant/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pep8-naming", "n"],
	"ruff_code": "N811",
	"ruff_linter": "pep8-naming",
	"ruff_name": "constant-imported-as-non-constant",
	"ruff_since": "v0.0.82",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^from\s+\S+\s+import\s+[a-z]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Constant imported as non-constant",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
