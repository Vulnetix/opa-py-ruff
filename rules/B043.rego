# SPDX-License-Identifier: Apache-2.0
# Ruff rule B043 (flake8-bugbear): del attr with constant
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b043

import rego.v1

metadata := {
	"id": "RUFF-B043",
	"name": "del attr with constant",
	"description": "Do not call `delattr` with a constant attribute value. It is not any safer than normal property deletion.",
	"help_uri": "https://docs.astral.sh/ruff/rules/del-attr-with-constant/",
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
	"ruff_code": "B043",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "del-attr-with-constant",
	"ruff_since": "0.15.6",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
