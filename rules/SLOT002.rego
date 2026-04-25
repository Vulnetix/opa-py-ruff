# SPDX-License-Identifier: Apache-2.0
# Ruff rule SLOT002 (flake8-slots): no slots in namedtuple subclass
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_slot002

import rego.v1

metadata := {
	"id": "RUFF-SLOT002",
	"name": "no slots in namedtuple subclass",
	"description": "Subclasses of <value> should define `__slots__`",
	"help_uri": "https://docs.astral.sh/ruff/rules/no-slots-in-namedtuple-subclass/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-slots", "slot"],
	"ruff_code": "SLOT002",
	"ruff_linter": "flake8-slots",
	"ruff_name": "no-slots-in-namedtuple-subclass",
	"ruff_since": "v0.0.273",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`class\s+\w+.*NamedTuple.*:\s*\n`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "NamedTuple subclass without __slots__",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
