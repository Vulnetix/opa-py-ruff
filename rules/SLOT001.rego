# SPDX-License-Identifier: Apache-2.0
# Ruff rule SLOT001 (flake8-slots): no slots in tuple subclass
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_slot001

import rego.v1

metadata := {
	"id": "RUFF-SLOT001",
	"name": "no slots in tuple subclass",
	"description": "Subclasses of `tuple` should define `__slots__`",
	"help_uri": "https://docs.astral.sh/ruff/rules/no-slots-in-tuple-subclass/",
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
	"ruff_code": "SLOT001",
	"ruff_linter": "flake8-slots",
	"ruff_name": "no-slots-in-tuple-subclass",
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
	regex.match(`class\s+\w+\s*\(\s*tuple\s*\).*:\s*\n(?!.*__slots__)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Subclass of tuple without __slots__",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
