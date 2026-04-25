# SPDX-License-Identifier: Apache-2.0
# Ruff rule NPY001 (NumPy-specific rules): numpy deprecated type alias
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_npy001

import rego.v1

metadata := {
	"id": "RUFF-NPY001",
	"name": "numpy deprecated type alias",
	"description": "Type alias `np.<value>` is deprecated, replace with builtin type",
	"help_uri": "https://docs.astral.sh/ruff/rules/numpy-deprecated-type-alias/",
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
	"ruff_code": "NPY001",
	"ruff_linter": "NumPy-specific rules",
	"ruff_name": "numpy-deprecated-type-alias",
	"ruff_since": "v0.0.247",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bnp\.bool\b(?!_)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use np.bool_ instead of deprecated np.bool",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
