# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI066 (flake8-pyi): bad version info order
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi066

import rego.v1

metadata := {
	"id": "RUFF-PYI066",
	"name": "bad version info order",
	"description": "Put branches for newer Python versions first when branching on `sys.version_info` comparisons",
	"help_uri": "https://docs.astral.sh/ruff/rules/bad-version-info-order/",
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
	"ruff_code": "PYI066",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "bad-version-info-order",
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
	regex.match(`if\s+sys\.version_info\s*[<>]=?\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Version comparison without sys version check",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
