# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI063 (flake8-pyi): pep484 style positional only parameter
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi063

import rego.v1

metadata := {
	"id": "RUFF-PYI063",
	"name": "pep484 style positional only parameter",
	"description": "Use PEP 570 syntax for positional-only parameters",
	"help_uri": "https://docs.astral.sh/ruff/rules/pep484-style-positional-only-parameter/",
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
	"ruff_code": "PYI063",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "pep484-style-positional-only-parameter",
	"ruff_since": "0.8.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`def\s+\w+\s*\(\s*self\s*\)\s*->`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Self-type annotation in method",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
