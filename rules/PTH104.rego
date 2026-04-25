# SPDX-License-Identifier: Apache-2.0
# Ruff rule PTH104 (flake8-use-pathlib): os rename
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pth104

import rego.v1

metadata := {
	"id": "RUFF-PTH104",
	"name": "os rename",
	"description": "`os.rename()` should be replaced by `Path.rename()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/os-rename/",
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
	"ruff_code": "PTH104",
	"ruff_linter": "flake8-use-pathlib",
	"ruff_name": "os-rename",
	"ruff_since": "v0.0.231",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bos\.rename\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use pathlib.Path.rename() instead of os.rename()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
