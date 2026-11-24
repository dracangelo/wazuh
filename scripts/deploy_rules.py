#!/usr/bin/env python3
"""
Automated Rule Exporter & Wazuh Deployer.

Validates, packages, exports, and automatically deploys custom Wazuh detection
rules to the Wazuh Manager using SSH/SCP or the Wazuh Manager REST API.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parents[1]
FRAMEWORK_DIR = ROOT_DIR / "framework"
VENV_DV = FRAMEWORK_DIR / ".venv" / "bin" / "dv"
RULES_LINUX = ROOT_DIR / "rules" / "wazuh" / "linux"
RULES_WINDOWS = ROOT_DIR / "rules" / "wazuh" / "windows"


def log(msg: str, color: str = "\033[0m") -> None:
    print(f"{color}{msg}\033[0m")


def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    proc = subprocess.run(cmd, cwd=str(ROOT_DIR), capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def lint_rules() -> bool:
    """Pre-flight check: ensures rule XML passes all structural and parent checks."""
    log("\n[1/5] Running pre-flight rule validation (dv rules-check)...", "\033[1;34m")
    if not VENV_DV.exists():
        log("Virtual environment binary 'dv' not found. Setting up...", "\033[1;33m")
        setup_rc = subprocess.run([str(ROOT_DIR / "scripts" / "run_tests.sh"), "--lint"]).returncode
        if setup_rc != 0:
            return False

    rc, out, err = run_cmd([str(VENV_DV), "rules-check"])
    if rc == 0:
        log("✔ Rule syntax, IDs, regexes, and parent hierarchies are 100% clean.", "\033[1;32m")
        return True
    else:
        log("✖ Wazuh rules-check failed:\n" + out + err, "\033[1;31m")
        return False


def collect_rule_files(platform: Optional[str] = None) -> List[Path]:
    """Gathers all active custom Wazuh rule XML files."""
    files: List[Path] = []
    if platform in (None, "linux"):
        files.extend(sorted(RULES_LINUX.glob("0*.xml")))
    if platform in (None, "windows"):
        files.extend(sorted(RULES_WINDOWS.glob("0*.xml")))
    return files


def export_bundle(output_tar: Path, platform: Optional[str] = None) -> Path:
    """Creates an export bundle archive of all rules and agent snippets."""
    rule_files = collect_rule_files(platform)
    log(f"\n[2/5] Packaging {len(rule_files)} rule files into export bundle...", "\033[1;34m")
    with tempfile.TemporaryDirectory() as tmp_dir:
        staging = Path(tmp_dir) / "wazuh-rules"
        staging.mkdir()
        for rf in rule_files:
            shutil.copy2(rf, staging / rf.name)

        # Include audit rules snippet
        audit_file = RULES_LINUX / "agent-config" / "audit" / "99-dv.rules"
        if audit_file.exists():
            (staging / "audit").mkdir()
            shutil.copy2(audit_file, staging / "audit" / "99-dv.rules")

        archive_stem = str(output_tar).rstrip(".tar.gz").rstrip(".tgz")
        shutil.make_archive(archive_stem, "gztar", tmp_dir)

    tar_path = Path(f"{archive_stem}.tar.gz")
    log(f"✔ Export bundle created at: {tar_path} ({tar_path.stat().st_size} bytes)", "\033[1;32m")
    return tar_path


def deploy_via_ssh(
    host: str,
    user: str = "root",
    port: int = 22,
    rules_dir: str = "/var/ossec/etc/rules",
    restart: bool = True,
    dry_run: bool = False,
    platform: Optional[str] = None,
) -> bool:
    """Deploys rules directly to Wazuh Manager over SSH/SCP."""
    rule_files = collect_rule_files(platform)
    log(f"\n[3/5] Deploying via SSH to {user}@{host}:{port}...", "\033[1;34m")

    if dry_run:
        log("DRY-RUN: The following files would be copied to " + rules_dir + ":", "\033[1;33m")
        for f in rule_files:
            log(f"  - {f.name} ({f.stat().st_size} bytes)")
        log("DRY-RUN: Permissions would be set to wazuh:wazuh 0640")
        log("DRY-RUN: Manager would be reloaded: /var/ossec/bin/wazuh-control restart")
        return True

    ssh_base = ["ssh", "-p", str(port), f"{user}@{host}"]

    # 1. Backup existing rules
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_dir = f"/var/ossec/etc/rules_backup_{ts}"
    log(f"Backing up existing manager rules to {backup_dir}...", "\033[0;37m")
    rc, _, err = run_cmd(ssh_base + [f"cp -r {rules_dir} {backup_dir} 2>/dev/null || true"])
    if rc != 0:
        log(f"Warning: backup step failed: {err.strip()}", "\033[1;33m")

    # 2. Copy files
    scp_cmd = ["scp", "-P", str(port)] + [str(f) for f in rule_files] + [f"{user}@{host}:{rules_dir}/"]
    log("Copying rule files...", "\033[0;37m")
    rc, out, err = run_cmd(scp_cmd)
    if rc != 0:
        log(f"✖ SCP transfer failed: {err.strip()}", "\033[1;31m")
        return False

    # 3. Set proper ownership
    log("Setting file ownership to wazuh:wazuh...", "\033[0;37m")
    chown_cmd = ssh_base + [f"chown wazuh:wazuh {rules_dir}/0*.xml && chmod 0640 {rules_dir}/0*.xml"]
    rc, _, err = run_cmd(chown_cmd)
    if rc != 0:
        log(f"Warning: permissions command returned non-zero: {err.strip()}", "\033[1;33m")

    # 4. Test configuration with wazuh-analysisd / wazuh-logtest if available
    log("Validating syntax on manager with wazuh-analysisd -t...", "\033[0;37m")
    test_cmd = ssh_base + ["/var/ossec/bin/wazuh-analysisd -t 2>&1 || true"]
    rc, out, _ = run_cmd(test_cmd)
    if "Configuration error" in out or "Invalid element" in out:
        log(f"✖ Manager validation failed on remote target:\n{out}", "\033[1;31m")
        log(f"Restoring backup from {backup_dir}...", "\033[1;33m")
        run_cmd(ssh_base + [f"cp -f {backup_dir}/* {rules_dir}/ 2>/dev/null || true"])
        return False

    # 5. Restart or reload manager service
    if restart:
        log("Restarting Wazuh manager service...", "\033[1;34m")
        restart_cmd = ssh_base + ["systemctl restart wazuh-manager || /var/ossec/bin/wazuh-control restart"]
        rc, out, err = run_cmd(restart_cmd)
        if rc != 0:
            log(f"✖ Manager restart failed: {err.strip()}", "\033[1;31m")
            return False
        log("✔ Wazuh manager restarted successfully.", "\033[1;32m")

    return True


def deploy_via_api(
    url: str,
    user: str,
    password: str,
    verify_tls: bool = False,
    dry_run: bool = False,
    platform: Optional[str] = None,
) -> bool:
    """Deploys rules using the Wazuh Manager REST API (/manager/files endpoint)."""
    import urllib3
    import requests
    if not verify_tls:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    rule_files = collect_rule_files(platform)
    log(f"\n[3/5] Deploying via Wazuh Manager API at {url}...", "\033[1;34m")

    if dry_run:
        log("DRY-RUN: The following files would be uploaded via API PUT /manager/files:", "\033[1;33m")
        for f in rule_files:
            log(f"  - etc/rules/{f.name}")
        log("DRY-RUN: Manager would be restarted via PUT /manager/restart")
        return True

    # 1. Authenticate to get JWT token
    auth_url = f"{url.rstrip('/')}/security/user/authenticate?raw=true"
    try:
        r = requests.post(auth_url, auth=(user, password), verify=verify_tls, timeout=15)
        r.raise_for_status()
        token = r.text.strip()
    except Exception as exc:
        log(f"✖ Wazuh API Authentication failed: {exc}", "\033[1;31m")
        return False

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"}

    # 2. Upload each rule file
    for rf in rule_files:
        endpoint = f"{url.rstrip('/')}/manager/files?path=etc/rules/{rf.name}&overwrite=true"
        log(f"Uploading {rf.name}...", "\033[0;37m")
        try:
            content = rf.read_bytes()
            put_res = requests.put(endpoint, data=content, headers=headers, verify=verify_tls, timeout=20)
            if put_res.status_code not in (200, 201):
                log(f"✖ Failed uploading {rf.name}: {put_res.text}", "\033[1;31m")
                return False
        except Exception as exc:
            log(f"✖ Upload error for {rf.name}: {exc}", "\033[1;31m")
            return False

    log(f"✔ All {len(rule_files)} rule files uploaded successfully.", "\033[1;32m")

    # 3. Request manager restart
    log("Restarting manager via API PUT /manager/restart...", "\033[1;34m")
    try:
        restart_res = requests.put(f"{url.rstrip('/')}/manager/restart", headers={"Authorization": f"Bearer {token}"}, verify=verify_tls, timeout=30)
        restart_res.raise_for_status()
        log("✔ Wazuh manager restart triggered.", "\033[1;32m")
    except Exception as exc:
        log(f"Warning: restart endpoint failed: {exc}", "\033[1;33m")

    return True


def main():
    parser = argparse.ArgumentParser(description="Wazuh Detection Rule Exporter & Automated Deployer")
    parser.add_argument("--export", metavar="FILE", help="Package all active rules into a .tar.gz bundle")
    parser.add_argument("--deploy-ssh", metavar="HOST", help="Deploy rules to target manager via SSH")
    parser.add_argument("--ssh-user", default="root", help="SSH username (default: root)")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--deploy-api", metavar="URL", help="Deploy rules via Wazuh REST API URL (e.g. https://10.0.0.10:55000)")
    parser.add_argument("--api-user", default=os.environ.get("WAZUH_API_USER", "wazuh-wui"), help="API user")
    parser.add_argument("--api-password", default=os.environ.get("WAZUH_API_PASSWORD", ""), help="API password")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification for API")
    parser.add_argument("--platform", choices=["linux", "windows"], help="Deploy/export only a specific platform ruleset")
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions without writing files or restarting services")
    parser.add_argument("--no-restart", action="store_true", help="Do not restart the Wazuh manager after deployment")

    args = parser.parse_args()

    # Pre-flight linting
    if not lint_rules():
        log("\nDeployment aborted due to validation errors.", "\033[1;31m")
        sys.exit(1)

    # 1. Export Bundle if requested
    if args.export:
        export_bundle(Path(args.export), platform=args.platform)

    # 2. SSH Deployment
    if args.deploy_ssh:
        success = deploy_via_ssh(
            host=args.deploy_ssh,
            user=args.ssh_user,
            port=args.ssh_port,
            restart=not args.no_restart,
            dry_run=args.dry_run,
            platform=args.platform,
        )
        if not success:
            sys.exit(1)

    # 3. API Deployment
    if args.deploy_api:
        if not args.api_password:
            log("API deployment requires --api-password or WAZUH_API_PASSWORD environment variable.", "\033[1;31m")
            sys.exit(1)
        success = deploy_via_api(
            url=args.deploy_api,
            user=args.api_user,
            password=args.api_password,
            verify_tls=not args.insecure,
            dry_run=args.dry_run,
            platform=args.platform,
        )
        if not success:
            sys.exit(1)

    if not args.export and not args.deploy_ssh and not args.deploy_api:
        log("\nRule validation passed. No deploy or export target specified.", "\033[1;33m")
        log("Usage examples:")
        log("  ./scripts/deploy_rules.py --export wazuh-rules-latest.tar.gz")
        log("  ./scripts/deploy_rules.py --deploy-ssh 10.0.0.10 --dry-run")
        log("  ./scripts/deploy_rules.py --deploy-api https://10.0.0.10:55000 --dry-run")

    log("\nDone.", "\033[1;32m")


if __name__ == "__main__":
    main()

