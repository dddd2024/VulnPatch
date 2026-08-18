"""Reset only competition-created cases and restore checked-in seed cases."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from env_config import load_project_env
load_project_env()

from knowledge.case_models import RepairCase
from knowledge.case_store import CaseStore

ROOT = Path(__file__).resolve().parent


def main() -> int:
    store = CaseStore()
    removed = store.reset_demo_cases()
    seed_path = ROOT / "seed_cases.json"
    seeds = json.loads(seed_path.read_text(encoding="utf-8"))
    for raw in seeds:
        store.add_case(RepairCase(**raw))
    cases = store.list_cases(limit=1000)
    print("VulnPatch competition demo reset")
    print(f"Removed demo cases: {removed}")
    print(f"Seed cases: {sum(bool(c.metadata.get('seed')) for c in cases)}")
    print(f"Positive cases: {sum(c.outcome == 'POSITIVE' for c in cases)}")
    print(f"Negative cases: {sum(c.outcome == 'NEGATIVE' for c in cases)}")
    print("READY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
