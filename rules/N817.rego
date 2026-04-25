# SPDX-License-Identifier: Apache-2.0
# Ruff rule N817 (pep8-naming): camelcase imported as acronym
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_n817

import rego.v1

metadata := {
	"id": "RUFF-N817",
	"name": "camelcase imported as acronym",
	"description": "CamelCase `<value>` imported as acronym `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/camelcase-imported-as-acronym/",
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
	"ruff_code": "N817",
	"ruff_linter": "pep8-naming",
	"ruff_name": "camelcase-imported-as-acronym",
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
	regex.match(`^from\s+\S+\s+import\s+\S+\s+as\s+[A-Z]{2,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "CamelCase imported as acronym",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
