# SPDX-License-Identifier: Apache-2.0
# Ruff rule PTH119 (flake8-use-pathlib): os path basename
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pth119

import rego.v1

metadata := {
	"id": "RUFF-PTH119",
	"name": "os path basename",
	"description": "`os.path.basename()` should be replaced by `Path.name`",
	"help_uri": "https://docs.astral.sh/ruff/rules/os-path-basename/",
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
	"ruff_code": "PTH119",
	"ruff_linter": "flake8-use-pathlib",
	"ruff_name": "os-path-basename",
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
	regex.match(`\bos\.path\.basename\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use pathlib.Path.name instead of os.path.basename()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
