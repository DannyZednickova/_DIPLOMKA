from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, Tuple

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

PIPELINE: Iterable[Tuple[str, Path]] = [
    ("OpenVAS -> Neo4j", BASE_DIR / "OpenVas_To_NEO.py"),
    ("CTI (CVE enrichment) -> Neo4j", BASE_DIR / "CVE_To_Neo.py"),
    ("IntrusionSet TARGETS Location -> Neo4j", BASE_DIR / "Intrusionset_targets_location_TONEO.py"),
    ("IntrusionSet USES Malware -> Neo4j", BASE_DIR / "Intrusionset_uses_malware_TONEO.py"),
    ("IntrusionSet USES AttackPattern -> Neo4j", BASE_DIR / "Intrusionset_uses_AttackPattern_TONEO.py"),
]


def _build_common_env() -> Dict[str, str]:
    env = os.environ.copy()
    for key in [
        "NEO4J_URI",
        "NEO4J_USER",
        "NEO4J_PASS",
        "NEO4J_DB",
        "OPENCTI_URL",
        "OPENCTI_TOKEN",
        "MODE",
        "CVE_LIST",
        "OPENCTI_PAGE_SIZE",
    ]:
        value = os.getenv(key)
        if value is not None:
            env[key] = value
    return env


def run_step(name: str, script_path: Path, env: Dict[str, str]) -> None:
    if not script_path.exists():
        raise FileNotFoundError(f"[{name}] Script not found: {script_path}")

    py = sys.executable
    print(f"\n=== STEP: {name} ===")
    print(f"RUN: {py} {script_path}")

    completed = subprocess.run(
        [py, str(script_path)],
        env=env,
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        check=False,
    )

    if completed.stdout:
        print(f"[{name}] STDOUT:\n{completed.stdout}")
    if completed.stderr:
        print(f"[{name}] STDERR:\n{completed.stderr}")

    if completed.returncode != 0:
        raise RuntimeError(f"[{name}] Failed with exit code {completed.returncode}")

    print(f"=== OK: {name} ===")


def main() -> None:
    env = _build_common_env()
    for name, script in PIPELINE:
        run_step(name, script, env)

    print("\n[PIPELINE OK] Všechny kroky doběhly úspěšně.")


if __name__ == "__main__":
    main()
