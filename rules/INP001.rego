# SPDX-License-Identifier: Apache-2.0
# Ruff rule INP001 (flake8-no-pep420): implicit namespace package
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_inp001

import rego.v1

metadata := {
	"id": "RUFF-INP001",
	"name": "implicit namespace package",
	"description": "File `<value>` is part of an implicit namespace package. Add an `__init__.py`.",
	"help_uri": "https://docs.astral.sh/ruff/rules/implicit-namespace-package/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-no-pep420", "inp"],
	"ruff_code": "INP001",
	"ruff_linter": "flake8-no-pep420",
	"ruff_name": "implicit-namespace-package",
	"ruff_since": "v0.0.225",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(``, line)
	finding := {
		"rule_id": metadata.id,
		"message": "File is part of an implicit namespace package",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
