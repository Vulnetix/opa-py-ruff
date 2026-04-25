# SPDX-License-Identifier: Apache-2.0
# Ruff rule NPY201 (NumPy-specific rules): numpy2 deprecation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_npy201

import rego.v1

metadata := {
	"id": "RUFF-NPY201",
	"name": "numpy2 deprecation",
	"description": "`np.<value>` will be removed in NumPy 2.0. <value>",
	"help_uri": "https://docs.astral.sh/ruff/rules/numpy2-deprecation/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "numpy-specific-rules", "npy"],
	"ruff_code": "NPY201",
	"ruff_linter": "NumPy-specific rules",
	"ruff_name": "numpy2-deprecation",
	"ruff_since": "v0.2.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bnp\.(string_|unicode_|complex_|object_)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Deprecated NumPy type alias",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
