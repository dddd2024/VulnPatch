"""Offline-safe preflight checks for a competition machine."""
from __future__ import annotations

import importlib.util
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

from env_config import load_project_env
load_project_env()

ROOT = Path(__file__).resolve().parent.parent


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"{name:<28} {'PASS' if ok else 'FAIL'} {detail}".rstrip())
    return ok


def main() -> int:
    results: list[bool] = []
    results.append(check("FastAPI", importlib.util.find_spec("fastapi") is not None))
    results.append(check("Pydantic", importlib.util.find_spec("pydantic") is not None))
    results.append(check("PyYAML", importlib.util.find_spec("yaml") is not None))

    required = [
        ROOT / "config" / "model_routing.yaml",
        ROOT / "demo" / "simple_sql" / "SimpleSql.java",
        ROOT / "demo" / "path_evolution" / "VulnerableDownload.java",
        ROOT / "demo" / "path_evolution" / "SimilarDownload.java",
        ROOT / "demo" / "path_evolution" / "traversal_vectors.json",
        ROOT / "demo" / "seed_cases.json",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    results.append(check("Demo fixture files", not missing, ", ".join(missing)))

    try:
        with tempfile.TemporaryDirectory(prefix="vulnpatch_preflight_") as tmp:
            db = Path(tmp) / "probe.db"
            conn = sqlite3.connect(db)
            conn.execute("CREATE TABLE probe(x INTEGER)")
            conn.close()
        db_ok = True
    except Exception as exc:
        db_ok = False
        print(f"SQLite detail: {exc}")
    results.append(check("SQLite writable", db_ok))

    javac = shutil.which("javac")
    results.append(check("Java compiler", bool(javac), javac or "optional but recommended"))

    cloud = any(os.getenv(name) for name in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY", "LLM_API_KEY"))
    local = bool(os.getenv("OLLAMA_BASE_URL") or os.getenv("OLLAMA_ENABLED", "").lower() in {"1", "true", "yes"})
    check("Cloud model configured", cloud, "LIVE cloud route enabled" if cloud else "rule/replay fallback available")
    check("Local model configured", local, "Ollama route enabled" if local else "rule fallback available")

    print("\nREADY FOR DEMO" if all(results[:-1]) else "\nPRECHECK HAS FAILURES")
    # javac is useful but a skipped compiler check does not block deterministic
    # security verification, so only core dependencies/fixtures/SQLite are fatal.
    fatal = results[:4]
    return 0 if all(fatal) else 1


if __name__ == "__main__":
    raise SystemExit(main())
