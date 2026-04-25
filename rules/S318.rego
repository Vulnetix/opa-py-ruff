# SPDX-License-Identifier: Apache-2.0
# Ruff rule S318 (flake8-bandit): suspicious xml mini dom usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s318

import rego.v1

metadata := {
	"id": "RUFF-S318",
	"name": "suspicious xml mini dom usage",
	"description": "Using `xml` to parse untrusted data is known to be vulnerable to XML attacks; use `defusedxml` equivalents",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-xml-mini-dom-usage/",
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
	"ruff_code": "S318",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-xml-mini-dom-usage",
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
	regex.match(`\bxml\.dom\.minidom\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "xml.dom.minidom is vulnerable",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
