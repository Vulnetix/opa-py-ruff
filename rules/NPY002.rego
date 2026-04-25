# SPDX-License-Identifier: Apache-2.0
# Ruff rule NPY002 (NumPy-specific rules): numpy legacy random
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_npy002

import rego.v1

metadata := {
	"id": "RUFF-NPY002",
	"name": "numpy legacy random",
	"description": "Replace legacy `np.random.<value>` call with `np.random.Generator`",
	"help_uri": "https://docs.astral.sh/ruff/rules/numpy-legacy-random/",
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
	"ruff_code": "NPY002",
	"ruff_linter": "NumPy-specific rules",
	"ruff_name": "numpy-legacy-random",
	"ruff_since": "v0.0.248",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bnp\.random\.\w+\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Replace legacy np.random call with rng",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
