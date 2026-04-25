# SPDX-License-Identifier: Apache-2.0
# Ruff rule PTH116 (flake8-use-pathlib): os stat
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pth116

import rego.v1

metadata := {
	"id": "RUFF-PTH116",
	"name": "os stat",
	"description": "`os.stat()` should be replaced by `Path.stat()`, `Path.owner()`, or `Path.group()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/os-stat/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-use-pathlib", "pth"],
	"ruff_code": "PTH116",
	"ruff_linter": "flake8-use-pathlib",
	"ruff_name": "os-stat",
	"ruff_since": "v0.0.231",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bos\.stat\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use pathlib.Path.stat() instead of os.stat()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
