#!/usr/bin/env python3

import yaml
import subprocess
import requests
from pathlib import Path
import copy
import sys
import os

# =========================
# CONFIGURATION (IaC friendly)
# =========================

KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601")
KIBANA_API = "/api/detection_engine/rules"
SIGMA_CLI = os.getenv("SIGMA_CLI", "sigma")

KIBANA_TOKEN = os.getenv("KIBANA_TOKEN")
KIBANA_AUTH_SCHEME = os.getenv("KIBANA_AUTH_SCHEME", "Bearer")

HEADERS = {
    "Content-Type": "application/json",
    "kbn-xsrf": "true"
}

# add Authorization ONLY if token exists
if KIBANA_TOKEN:
    HEADERS["Authorization"] = f"{KIBANA_AUTH_SCHEME} {KIBANA_TOKEN}"

# =========================
# UTILS
# =========================

def load_yaml(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def deep_merge(base: dict, override: dict):
    for k, v in override.items():
        if isinstance(v, dict) and k in base and isinstance(base[k], dict):
            deep_merge(base[k], v)
        else:
            base[k] = v

def sigma_to_kql(sigma_file: Path) -> str:
    try:
        result = subprocess.check_output(
            [
                SIGMA_CLI,
                "convert",
                "-t", "lucene",
                "-p", "ecs",
                str(sigma_file)
            ],
            stderr=subprocess.STDOUT,
            env=os.environ
        )
        return result.decode("utf-8").strip()
    except subprocess.CalledProcessError as e:
        print(f"[!] Sigma conversion failed for {sigma_file}")
        print(e.output.decode())
        sys.exit(1)

def severity_to_risk(severity: str) -> int:
    return {
        "low": 21,
        "medium": 47,
        "high": 73,
        "critical": 99
    }.get(severity.lower(), 21)

# =========================
# CORE LOGIC
# =========================

def build_rule(sigma: dict, meta: dict, query: str) -> dict:
    elastic = meta.get("elastic", {})
    severity = elastic.get("severity", "low")

    rule = {
        "rule_id": sigma.get("id") or sigma.get("title"),
        "name": sigma.get("title"),
        "description": sigma.get("description", "Converted from Sigma rule"),
        "enabled": True,
        "index": [elastic.get("index", "logs-*")],
        "interval": elastic.get("interval", "1m"),
        "severity": severity,
        "risk_score": elastic.get("risk_score", severity_to_risk(severity)),
        "tags": sigma.get("tags", []),
        "query": query,
        "language": "kuery",
        "type": elastic.get("rule_type", "query")
    }

    if rule["type"] == "threshold":
        if "threshold" not in elastic:
            raise ValueError(f"Missing threshold config for {rule['name']}")

        rule["threshold"] = {
            "field": elastic["threshold"]["field"],
            "value": elastic["threshold"]["value"]
        }

        timeframe = elastic.get("timeframe", "1m")
        rule["from"] = f"now-{timeframe}"

    return rule

def deploy_rule(rule: dict):
    url = KIBANA_URL.rstrip("/") + KIBANA_API
    response = requests.post(url, headers=HEADERS, json=rule)

    if response.status_code in (200, 201):
        print(f"[+] Deployed: {rule['name']}")
    elif response.status_code == 409:
        print(f"[*] Already exists: {rule['name']}")
    else:
        print(f"[X] Failed: {rule['name']}")
        print(f"Status: {response.status_code}")
        print(response.text)

# =========================
# ENTRY POINT
# =========================

def main():
    script_dir = Path(__file__).resolve().parent
    base_path = script_dir.parent / "detections"
    defaults_file = base_path / "defaults.meta.yml"

    if not defaults_file.exists():
        print(f"[!] defaults.meta.yml not found: {defaults_file}")
        sys.exit(1)

    global_defaults = load_yaml(defaults_file)

    for sigma_file in base_path.glob("**/*.yml"):
        if sigma_file.name.endswith(".meta.yml") or sigma_file.name == "defaults.meta.yml":
            continue

        print(f"[>] Processing {sigma_file}")

        sigma_content = load_yaml(sigma_file)

        merged_meta = copy.deepcopy(global_defaults)
        meta_file = sigma_file.with_suffix(".meta.yml")
        if meta_file.exists():
            deep_merge(merged_meta, load_yaml(meta_file))

        kql_query = sigma_to_kql(sigma_file)
        rule = build_rule(sigma_content, merged_meta, kql_query)
        deploy_rule(rule)

if __name__ == "__main__":
    main()
