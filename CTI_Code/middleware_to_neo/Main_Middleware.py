import os
import sys
import subprocess
from pathlib import Path
from dotenv import load_dotenv

# Načti .env
load_dotenv()

# Root projektu (adresář, kde leží tento middleware)
BASE_DIR = Path(__file__).resolve().parent

# Skripty
SCRIPTS_DIR = BASE_DIR  # nebo BASE_DIR / "middleware_to_neo"

# Seznam kroků (sekvenčně)
PIPELINE = [
    ("OpenVAS -> Neo4j",            SCRIPTS_DIR / "OpenVas_To_NEO.py"),
    ("MITRE ATT&CK Patterns -> Neo4j", SCRIPTS_DIR / "Mitre_Attack_Pattern_To_NEO.py"),
    ("MITRE Groups -> Neo4j",       SCRIPTS_DIR / "Mitre_Groups_to_Neo.py"),
    ("MITRE Software -> Neo4j",     SCRIPTS_DIR / "Mitre_SW_to_Neo.py"),
]

def run_step(name: str, script_path: Path, extra_env: dict | None = None) -> None:
    """
    Spustí jeden python skript a BLOKUJE (čeká), dokud neskončí.
    Při chybě vyhodí RuntimeError.
    """
    if not script_path.exists():
        raise FileNotFoundError(f"[{name}] Script not found: {script_path}")

    env = os.environ.copy()
    if extra_env:
        env.update({k: str(v) for k, v in extra_env.items()})

    py = sys.executable  # stejný python/venv
    print(f"\n=== STEP: {name} ===")
    print(f"RUN: {py} {script_path}")

    completed = subprocess.run(
        [py, str(script_path)],
        env=env,
        cwd=str(SCRIPTS_DIR),   # pracovní adresář, aby seděly relativní cesty
        capture_output=True,
        text=True,
        check=False
    )

    # Logy
    if completed.stdout:
        print(f"[{name}] STDOUT:\n{completed.stdout}")
    if completed.stderr:
        print(f"[{name}] STDERR:\n{completed.stderr}")

    if completed.returncode != 0:
        raise RuntimeError(f"[{name}] Failed with exit code {completed.returncode}")

    print(f"=== OK: {name} ===")

def main():
    # Volitelné: můžeš poslat všem krokům stejné env proměnné
    common_env = {
        "NEO4J_URI": os.getenv("NEO4J_URI"),
        "NEO4J_USER": os.getenv("NEO4J_USER"),
        "NEO4J_PASS": os.getenv("NEO4J_PASS"),
        "NEO4J_DB": os.getenv("NEO4J_DB"),
    }

    for name, script in PIPELINE:
        run_step(name, script, extra_env=common_env)

    print("\n Pipeline hotová: všechny skripty doběhly úspěšně.")

if __name__ == "__main__":
    main()
