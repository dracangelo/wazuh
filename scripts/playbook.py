#!/usr/bin/env python3
"""
Detection Playbook & Simulation Runner
Interactive and automated CLI suite to execute detection playbooks across MITRE tactics,
platforms (Linux/Windows), and test types (Atomic Red Team, custom simulations).
"""
import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]
FRAMEWORK_DIR = ROOT_DIR / "framework"
VENV_DV = FRAMEWORK_DIR / ".venv" / "bin" / "dv"
VENV_PYTEST = FRAMEWORK_DIR / ".venv" / "bin" / "pytest"

PLAYBOOKS = {
    "smoke": {
        "title": "Smoke & Health Check Playbook",
        "description": "Verifies ingestion pipeline markers (syslog, FIM, auditd, web, sysmon).",
        "tag": "smoke",
        "filter": {"tags": ["smoke", "pipeline"]}
    },
    "credential-access": {
        "title": "Credential Access & Theft Playbook",
        "description": "Simulates /etc/shadow reads, SSH brute-force, memory dumps, and Windows failed logons.",
        "techniques": ["T1003", "T1110"]
    },
    "defense-evasion": {
        "title": "Defense Evasion & Anti-Forensics Playbook",
        "description": "Exercises log tampering, firewall disabling, SELinux alteration, and timestomping.",
        "techniques": ["T1070", "T1562", "T1564"]
    },
    "execution": {
        "title": "Suspicious Execution & Reverse Shells Playbook",
        "description": "Validates /tmp execution, ncat shells, script-engine payloads, and PowerShell commands.",
        "techniques": ["T1059", "T1105", "T1095"]
    },
    "discovery": {
        "title": "Discovery & Reconnaissance Burst Playbook",
        "description": "Tests single discovery benign actions vs rapid discovery command bursts.",
        "techniques": ["T1082", "T1033", "T1087", "T1046", "T1482"]
    },
    "persistence": {
        "title": "Persistence & Account Manipulation Playbook",
        "description": "Simulates local account additions, cron modifications, and systemd/service creations.",
        "techniques": ["T1136", "T1098", "T1053", "T1543"]
    },
    "cloud": {
        "title": "Cloud Infrastructure & Identity Anomaly Playbook",
        "description": "Simulates AWS CloudTrail root logins/stop-trail, Azure Entra ID risky logins, and GCP IAM changes.",
        "tag": "cloud",
        "techniques": ["T1078.004", "T1562.001", "T1098"]
    },
    "container": {
        "title": "Container Breakout & Kubernetes Security Playbook",
        "description": "Simulates host Docker socket access, privileged container creation, and K8s token exfiltration.",
        "tag": "container",
        "techniques": ["T1611", "T1610", "T1552.007"]
    },
    "network-ids": {
        "title": "Network IDS & C2 Suricata Beaconing Playbook",
        "description": "Exercises Suricata EVE alerts for Cobalt Strike, Sliver C2, and DNS tunneling.",
        "tag": "network",
        "techniques": ["T1071.001", "T1071.004"]
    },
    "all": {
        "title": "Full Threat Matrix Playbook",
        "description": "Executes all positive and negative detection test cases across the catalog.",
        "all": True
    }
}


def log(msg: str, color: str = "\033[0m") -> None:
    print(f"{color}{msg}\033[0m")


def run_command(cmd: List[str], env: Optional[Dict[str, str]] = None) -> int:
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    return subprocess.run(cmd, cwd=str(ROOT_DIR), env=run_env).returncode


def get_catalog_tests() -> List[Dict]:
    cmd = [str(VENV_DV), "list"]
    proc = subprocess.run(cmd, cwd=str(ROOT_DIR), capture_output=True, text=True)
    tests = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 6:
            test_id, technique, platform, source, verdict_type = parts[0], parts[1], parts[2], parts[3], parts[4]
            desc = " ".join(parts[5:])
            tests.append({
                "id": test_id,
                "technique": technique,
                "platform": platform,
                "source": source,
                "verdict_type": verdict_type,
                "name": desc
            })
    return tests


def show_playbooks():
    log("\n=======================================================", "\033[1;36m")
    log("           WAZUH DETECTION SIMULATION PLAYBOOKS         ", "\033[1;36m")
    log("=======================================================", "\033[1;36m")
    for key, info in PLAYBOOKS.items():
        log(f"\n▶ [{key}] - {info['title']}", "\033[1;33m")
        log(f"  {info['description']}", "\033[0;37m")
        if "techniques" in info:
            log(f"  Techniques: {', '.join(info['techniques'])}", "\033[0;32m")
    print()


def execute_playbook(playbook_key: str, dry_run: bool = True, platform: Optional[str] = None):
    if playbook_key not in PLAYBOOKS:
        log(f"Unknown playbook: {playbook_key}", "\033[1;31m")
        show_playbooks()
        sys.exit(1)

    pb = PLAYBOOKS[playbook_key]
    log(f"\n🚀 Running Playbook: {pb['title']}", "\033[1;32m")
    log(f"Description: {pb['description']}\n", "\033[0;37m")

    cmd = [str(VENV_DV), "run"]
    if dry_run:
        cmd.append("--dry-run")
    if platform:
        cmd.extend(["--platform", platform])

    if pb.get("all"):
        pass  # run full catalog
    elif "tag" in pb:
        cmd.extend(["--tag", pb["tag"]])
    elif "techniques" in pb:
        for tech in pb["techniques"]:
            t_cmd = list(cmd) + ["--technique", tech]
            log(f"--- Technique Batch: {tech} ---", "\033[1;34m")
            run_command(t_cmd)
        return

    run_command(cmd)


def main():
    parser = argparse.ArgumentParser(description="Wazuh Detection Simulation Playbook Runner")
    parser.add_argument("playbook", nargs="?", default="list", help="Playbook name to run or 'list' to show available")
    parser.add_argument("--execute", action="store_true", help="Execute real simulations on lab targets (requires DV_LAB_ACK=1)")
    parser.add_argument("--platform", choices=["linux", "windows"], help="Filter by target platform")
    parser.add_argument("--matrix", action="store_true", help="Display full MITRE ATT&CK coverage matrix")
    parser.add_argument("--replay", help="Replay alert NDJSON file offline without lab hosts")


    args = parser.parse_args()

    if not VENV_DV.exists():
        log("Virtual environment binary 'dv' not found. Run ./scripts/run_tests.sh first.", "\033[1;31m")
        sys.exit(1)

    if args.matrix:
        run_command([str(VENV_DV), "coverage"])
        sys.exit(0)

    if args.replay:
        log(f"\n🔄 Running Offline Alert Replay from: {args.replay}", "\033[1;36m")
        replay_cmd = [str(VENV_DV), "replay", "--alerts", args.replay]
        if args.platform:
            replay_cmd.extend(["--platform", args.platform])
        if args.playbook and args.playbook != "list":
            pb = PLAYBOOKS.get(args.playbook)
            if pb and "techniques" in pb:
                for tech in pb["techniques"]:
                    log(f"--- Replaying Technique: {tech} ---", "\033[1;34m")
                    run_command(replay_cmd + ["--technique", tech])
                sys.exit(0)
            elif pb and "tag" in pb:
                replay_cmd.extend(["--tag", pb["tag"]])
        run_command(replay_cmd)
        sys.exit(0)


    if args.playbook == "list" or not args.playbook:
        show_playbooks()
        tests = get_catalog_tests()
        log(f"Total catalog tests available: {len(tests)}", "\033[1;32m")
        log("Run 'python3 scripts/playbook.py <playbook-name> [--execute]' to start a simulation run.", "\033[1;35m")
        sys.exit(0)

    dry_run = not args.execute
    if not dry_run and os.environ.get("DV_LAB_ACK") != "1":
        log("Execution mode requires DV_LAB_ACK=1 acknowledgment for disposable lab safety.", "\033[1;31m")
        sys.exit(1)

    execute_playbook(args.playbook, dry_run=dry_run, platform=args.platform)


if __name__ == "__main__":
    main()

