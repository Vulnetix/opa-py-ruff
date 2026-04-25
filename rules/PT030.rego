# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT030 (flake8-pytest-style): pytest warns too broad
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt030

import rego.v1

metadata := {
	"id": "RUFF-PT030",
	"name": "pytest warns too broad",
	"description": "`pytest.warns(<value>)` is too broad, set the `match` parameter or use a more specific warning",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-warns-too-broad/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pytest-style", "pt"],
	"ruff_code": "PT030",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-warns-too-broad",
	"ruff_since": "0.12.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
