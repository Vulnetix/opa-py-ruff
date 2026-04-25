# SPDX-License-Identifier: Apache-2.0
# Ruff rule S406 (flake8-bandit): suspicious xml sax import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s406

import rego.v1

metadata := {
	"id": "RUFF-S406",
	"name": "suspicious xml sax import",
	"description": "`xml.sax` methods are vulnerable to XML attacks",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-xml-sax-import/",
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
	"ruff_code": "S406",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-xml-sax-import",
	"ruff_since": "v0.1.12",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^import\s+xml\b|^from\s+xml\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "xml module is vulnerable to XML attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
