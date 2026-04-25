# SPDX-License-Identifier: Apache-2.0
# Ruff rule B034 (flake8-bugbear): re sub positional args
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b034

import rego.v1

metadata := {
	"id": "RUFF-B034",
	"name": "re sub positional args",
	"description": "`<value>` should pass `<value>` and `flags` as keyword arguments to avoid confusion due to unintuitive argument positions",
	"help_uri": "https://docs.astral.sh/ruff/rules/re-sub-positional-args/",
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
	"ruff_code": "B034",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "re-sub-positional-args",
	"ruff_since": "v0.0.278",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`re\.(split|sub|subn|fullmatch|search|match|findall)\s*\([^,]+,\s*[^,]+,\s*[^,]+,\s*flags`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "re function with positional flags arg",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
