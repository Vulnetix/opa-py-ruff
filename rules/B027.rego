# SPDX-License-Identifier: Apache-2.0
# Ruff rule B027 (flake8-bugbear): empty method without abstract decorator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b027

import rego.v1

metadata := {
	"id": "RUFF-B027",
	"name": "empty method without abstract decorator",
	"description": "`<value>` is an empty method in an abstract base class, but has no abstract decorator",
	"help_uri": "https://docs.astral.sh/ruff/rules/empty-method-without-abstract-decorator/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B027",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "empty-method-without-abstract-decorator",
	"ruff_since": "v0.0.118",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`def\s+\w+\s*\([^)]*\)\s*:\s*\n\s*pass`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Abstract method without @abstractmethod decorator",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
