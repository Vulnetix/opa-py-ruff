# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP036 (pyupgrade): outdated version block
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up036

import rego.v1

metadata := {
	"id": "RUFF-UP036",
	"name": "outdated version block",
	"description": "Version block is outdated for minimum Python version",
	"help_uri": "https://docs.astral.sh/ruff/rules/outdated-version-block/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP036",
	"ruff_linter": "pyupgrade",
	"ruff_name": "outdated-version-block",
	"ruff_since": "v0.0.240",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`sys\.version_info\s*[<>=!]+\s*\(\s*[012]\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "sys.version_info comparison for Python 2",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
