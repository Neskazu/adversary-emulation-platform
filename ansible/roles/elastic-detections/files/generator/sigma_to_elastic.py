#!/usr/bin/env python3
import os
import yaml
import subprocess
import requests
from pathlib import Path
import copy
import sys
from requests.auth import HTTPBasicAuth

# =========================
# CONFIG
# =========================

# Путь к sigma-cli (берем из окружения или ищем дефолт)
SIGMA_CLI = os.getenv("SIGMA_CLI", "/opt/sigma-pipeline/.venv/bin/sigma")
SIGMA_PIPELINE = os.getenv("SIGMA_PIPELINE", "ecs_windows")

# КРЕДЕНШЕНЫ: Важно! Пароль должен совпадать с тем, что мы задали через curl
ELASTIC_USER = os.getenv("ELASTIC_USER", "sigma")
ELASTIC_PASS = os.getenv("ELASTIC_PASSWORD", "SuperStrongSigmaPassw0rd!") 
KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601")

HEADERS = {
    "Content-Type": "application/json",
    "kbn-xsrf": "true"
}

# =========================
# UTILS
# =========================

def load_yaml(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def deep_merge(base: dict, override: dict):
    for k, v in override.items():
        if isinstance(v, dict) and k in base:
            deep_merge(base[k], v)
        else:
            base[k] = v

def sigma_to_lucene(sigma_file: Path) -> str:
    try:
        result = subprocess.check_output(
            [SIGMA_CLI, "convert", "-t", "lucene", "-p", SIGMA_PIPELINE, str(sigma_file)],
            stderr=subprocess.STDOUT
        ).decode("utf-8").strip()
        
        lines = [line for line in result.splitlines() if line.strip()]
        return lines[-1] if lines else ""
    except subprocess.CalledProcessError as e:
        print(f"[X] Sigma convert failed: {sigma_file}")
        sys.exit(1)

def severity_to_risk(severity: str) -> int:
    return {
        "low": 21,
        "medium": 47,
        "high": 73,
        "critical": 99
    }.get(severity.lower(), 21)

# =========================
# RULE BUILD
# =========================

def build_rule(sigma: dict, meta: dict, query: str) -> dict:
    elastic = meta.get("elastic", {})
    severity = elastic.get("severity", "low")

    rule = {
        "rule_id": sigma["id"],
        "name": sigma["title"],
        "description": sigma.get("description", "Converted from Sigma"),
        "enabled": True,
        "index": [elastic.get("index", "logs-*")],
        "interval": elastic.get("interval", "1m"),
        "severity": severity,
        "risk_score": elastic.get("risk_score", severity_to_risk(severity)),
        "tags": sigma.get("tags", []),
        "query": query,
        "language": "lucene",
        "type": elastic.get("rule_type", "query")
    }

    if rule["type"] == "threshold":
        threshold = elastic.get("threshold")
        if not threshold:
            raise ValueError(f"Missing threshold config for {sigma['title']}")

        rule["threshold"] = {
            "field": threshold["field"],
            "value": threshold["value"]
        }

        timeframe = elastic.get("timeframe", "1m")
        rule["from"] = f"now-{timeframe}"

    return rule

# =========================
# DEPLOY
# =========================

def deploy_rule(rule: dict):
    url = f"{KIBANA_URL}/api/detection_engine/rules"

    # 1. Пытаемся СОЗДАТЬ правило
    r = requests.post(
        url,
        headers=HEADERS,
        auth=HTTPBasicAuth(ELASTIC_USER, ELASTIC_PASS),
        json=rule,
        timeout=60
    )

    # Успешно создано
    if r.status_code in (200, 201):
        print(f"[+] Created: {rule['name']}")
        return

    # 2. Уже существует -> ОБНОВЛЯЕМ
    if r.status_code == 409:
        update_url = f"{KIBANA_URL}/api/detection_engine/rules"

        r = requests.put(
            update_url,
            headers=HEADERS,
            auth=HTTPBasicAuth(ELASTIC_USER, ELASTIC_PASS),
            json=rule,
            timeout=30
        )

        if r.status_code == 200:
            print(f"[~] Updated: {rule['name']}")
            return

        print(f"[X] Update failed: {rule['name']} ({r.status_code})")
        print(f"Detail: {r.text}")
        sys.exit(1)

    # 3. Любая другая ошибка
    print(f"[X] Create failed: {rule['name']} ({r.status_code})")
    print(f"Detail: {r.text}")
    sys.exit(1)


# =========================
# MAIN
# =========================

def main():
    script_dir = Path(__file__).resolve().parent
    base_path = script_dir.parent / "detections"

    defaults_file = base_path / "defaults.meta.yml"

    if not defaults_file.exists():
        base_path = script_dir / "detections"
        defaults_file = base_path / "defaults.meta.yml"

    if not defaults_file.exists():
        print(f"[X] defaults.meta.yml not found. Checked: {defaults_file.absolute()}")
        sys.exit(1)

    print(f"[*] Starting pipeline. Base path: {base_path.absolute()}")

    # 1. Load global defaults (low baseline)
    global_defaults = load_yaml(defaults_file)

    profiles_path = base_path / "profiles"

    found_rules = 0
    for sigma_file in base_path.glob("**/*.yml"):
        # Skip meta files and defaults
        if (
            sigma_file.name.endswith(".meta.yml")
            or sigma_file.name == "defaults.meta.yml"
        ):
            continue

        found_rules += 1
        print(f"[>] Processing: {sigma_file.relative_to(base_path)}")

        sigma_rule = load_yaml(sigma_file)

        # 2. Start with defaults
        merged_meta = copy.deepcopy(global_defaults)

        # 3. Apply severity profile (low / medium / high)
        level = sigma_rule.get("level", "low").lower()
        profile_file = profiles_path / f"{level}.meta.yml"

        if profile_file.exists():
            print(f"    [+] Applying profile: {level}")
            deep_merge(merged_meta, load_yaml(profile_file))

        # 4. Apply rule-specific meta override
        meta_file = sigma_file.with_suffix(".meta.yml")
        if meta_file.exists():
            print(f"    [+] Applying rule meta: {meta_file.name}")
            deep_merge(merged_meta, load_yaml(meta_file))

        # 5. Convert Sigma → Lucene
        lucene_query = sigma_to_lucene(sigma_file)

        # 6. Build and deploy rule
        rule = build_rule(sigma_rule, merged_meta, lucene_query)
        deploy_rule(rule)

    if found_rules == 0:
        print("[!] No Sigma rules found in the detections directory.")


if __name__ == "__main__":
    main()