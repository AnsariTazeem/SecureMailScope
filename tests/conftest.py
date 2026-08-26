"""Pytest bootstrap: expose fixture script modules to unit tests.

Fixture tooling lives in scripts/ outside the installed package on purpose
(ground truth must never import analyzer code), so the directory is added to
sys.path here.
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
