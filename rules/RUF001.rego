# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF001 (Ruff-specific rules): ambiguous unicode character string
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf001

import rego.v1

metadata := {
	"id": "RUFF-RUF001",
	"name": "ambiguous unicode character string",
	"description": "String contains ambiguous {}. Did you mean {}?",
	"help_uri": "https://docs.astral.sh/ruff/rules/ambiguous-unicode-character-string/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF001",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "ambiguous-unicode-character-string",
	"ruff_since": "v0.0.102",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`[ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρστυφχψω]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Ambiguous unicode character in string",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
