# SPDX-License-Identifier: Apache-2.0
# Ruff rule S316 (flake8-bandit): suspicious xml expat builder usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s316

import rego.v1

metadata := {
	"id": "RUFF-S316",
	"name": "suspicious xml expat builder usage",
	"description": "Using `xml` to parse untrusted data is known to be vulnerable to XML attacks; use `defusedxml` equivalents",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-xml-expat-builder-usage/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S316",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-xml-expat-builder-usage",
	"ruff_since": "v0.0.258",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bxml\.sax\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "xml.sax is vulnerable to XML attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
