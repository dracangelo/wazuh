#!/usr/bin/env python3
"""
Automatic Sigma-to-Wazuh Rule Compiler.

Translates Sigma detection rules (YAML) into native Wazuh detection rules (XML),
mapping log sources, parent rule IDs, MITRE ATT&CK techniques, and condition expressions.
"""
from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.dom import minidom

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
SIGMA_LINUX = ROOT_DIR / "rules" / "sigma" / "linux"
SIGMA_WINDOWS = ROOT_DIR / "rules" / "sigma" / "windows"
WAZUH_LINUX = ROOT_DIR / "rules" / "wazuh" / "linux"
WAZUH_WINDOWS = ROOT_DIR / "rules" / "wazuh" / "windows"

LEVEL_MAP = {
    "informational": 3,
    "low": 5,
    "medium": 8,
    "high": 11,
    "critical": 14,
}

PARENT_MAP = {
    # Linux process creation: child of auditd dv_exec base rule
    ("linux", "process_creation"): "100400",
    # Windows process creation: child of Sysmon Event 1 base rule
    ("windows", "process_creation"): "100712",
}

FIELD_MAP = {
    "linux": {
        "Image": "audit.exe",
        "CommandLine": "audit.execve",
    },
    "windows": {
        "Image": "win.eventdata.image",
        "CommandLine": "win.eventdata.commandLine",
        "ParentImage": "win.eventdata.parentImage",
        "TargetFilename": "win.eventdata.targetFilename",
        "TargetObject": "win.eventdata.targetObject",
    },
}


def sanitize_regex_token(val: str) -> str:
    """Escapes special regex characters while preserving words and patterns."""
    return re.escape(val).replace("\\ ", "\\s+")


def compile_sigma_detection(
    platform: str, detection: Dict[str, Any]
) -> Tuple[Optional[str], Optional[str]]:
    """
    Extracts field matcher and regex patterns from Sigma detection block.
    Returns (exe_pattern, cmdline_pattern).
    """
    fields_info = FIELD_MAP.get(platform, {})
    exe_field = fields_info.get("Image", "audit.exe" if platform == "linux" else "win.eventdata.image")
    cmd_field = fields_info.get("CommandLine", "audit.execve" if platform == "linux" else "win.eventdata.commandLine")

    exe_patterns: List[str] = []
    cmd_patterns: List[str] = []

    for key, val in detection.items():
        if key in ("condition", "timeframe"):
            continue
        if not isinstance(val, dict):
            continue

        for f_name, f_val in val.items():
            base_f = f_name.split("|")[0]
            val_list = f_val if isinstance(f_val, list) else [f_val]
            escaped = [sanitize_regex_token(str(v)) for v in val_list if str(v).strip()]

            if not escaped:
                continue

            pattern = "|".join(escaped) if len(escaped) > 1 else escaped[0]

            if base_f == "Image":
                exe_patterns.append(pattern)
            elif base_f == "CommandLine":
                cmd_patterns.append(pattern)

    combined_exe = "|".join(exe_patterns) if exe_patterns else None
    combined_cmd = "|".join(cmd_patterns) if cmd_patterns else None

    return combined_exe, combined_cmd


def compile_sigma_rule(
    sigma_path: Path, rule_id: int
) -> Optional[ET.Element]:
    """Compiles a single Sigma YAML file into a Wazuh <rule> Element."""
    try:
        doc = yaml.safe_load(sigma_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Error loading {sigma_path}: {exc}", file=sys.stderr)
        return None

    if not isinstance(doc, dict):
        return None

    logsource = doc.get("logsource", {})
    platform = logsource.get("product", "linux").lower()
    category = logsource.get("category", "process_creation").lower()

    parent_id = PARENT_MAP.get((platform, category))
    if not parent_id:
        # Fallback to standard base rules
        parent_id = "100400" if platform == "linux" else "100712"

    level = LEVEL_MAP.get(str(doc.get("level", "medium")).lower(), 8)
    title = doc.get("title", "Compiled Sigma Rule")

    rule_elem = ET.Element("rule", {"id": str(rule_id), "level": str(level)})

    if_sid = ET.SubElement(rule_elem, "if_sid")
    if_sid.text = parent_id

    detection = doc.get("detection", {})
    exe_pat, cmd_pat = compile_sigma_detection(platform, detection)

    if exe_pat:
        if platform == "linux":
            f_elem = ET.SubElement(rule_elem, "field", {"name": "audit.exe", "type": "pcre2"})
            f_elem.text = f"(?i)({exe_pat})"
        else:
            f_elem = ET.SubElement(rule_elem, "field", {"name": "win.eventdata.image", "type": "pcre2"})
            f_elem.text = f"(?i)({exe_pat})"

    if cmd_pat:
        if platform == "linux":
            # For auditd, plain arguments can be matched with regex or match
            r_elem = ET.SubElement(rule_elem, "regex", {"type": "pcre2"})
            r_elem.text = f"(?i)({cmd_pat})"
        else:
            f_elem = ET.SubElement(rule_elem, "field", {"name": "win.eventdata.commandLine", "type": "pcre2"})
            f_elem.text = f"(?i)({cmd_pat})"

    desc_elem = ET.SubElement(rule_elem, "description")
    desc_elem.text = f"Sigma: {title}"

    # MITRE ATT&CK techniques
    mitre_tags = [
        str(t).replace("attack.", "").upper()
        for t in doc.get("tags", [])
        if str(t).startswith("attack.t")
    ]
    if mitre_tags:
        mitre_elem = ET.SubElement(rule_elem, "mitre")
        for tech in mitre_tags:
            id_elem = ET.SubElement(mitre_elem, "id")
            id_elem.text = tech

    group_elem = ET.SubElement(rule_elem, "group")
    group_elem.text = "sigma_compiled,attack_tooling,"

    return rule_elem


def format_xml(elem: ET.Element) -> str:
    """Pretty prints XML element with proper indentation, omitting XML declaration for Wazuh rule file compatibility."""
    rough = ET.tostring(elem, "utf-8")
    reparsed = minidom.parseString(rough)
    # Wazuh rules files are standard XML snippets that do not use <?xml ... ?> declarations
    lines = [line for line in reparsed.toprettyxml(indent="  ").splitlines() if not line.strip().startswith("<?xml")]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Automatic Sigma-to-Wazuh Rule Compiler")
    parser.add_argument("--sigma", help="Path to single Sigma YAML rule")
    parser.add_argument("--all", action="store_true", help="Compile all Sigma rules in repository")
    parser.add_argument("--start-id", type=int, default=100950, help="Starting Wazuh Rule ID (default: 100950)")
    parser.add_argument("--output", help="Write compiled rules XML to file")
    parser.add_argument("--platform", choices=["linux", "windows"], help="Filter by platform")

    args = parser.parse_args()

    sigma_files: List[Path] = []
    if args.sigma:
        sigma_files.append(Path(args.sigma))
    elif args.all:
        if args.platform in (None, "linux"):
            sigma_files.extend(sorted(SIGMA_LINUX.glob("*.yml")))
        if args.platform in (None, "windows"):
            sigma_files.extend(sorted(SIGMA_WINDOWS.glob("*.yml")))
    else:
        parser.print_help()
        sys.exit(1)

    root_group = ET.Element("group", {"name": "local,sigma,dv_validation,"})
    current_id = args.start_id
    compiled_count = 0

    for s_path in sigma_files:
        rule_elem = compile_sigma_rule(s_path, current_id)
        if rule_elem is not None:
            root_group.append(rule_elem)
            current_id += 1
            compiled_count += 1

    xml_content = format_xml(root_group)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(xml_content, encoding="utf-8")
        print(f"✔ Successfully compiled {compiled_count} Sigma rules to: {out_path}")
    else:
        print(xml_content)


if __name__ == "__main__":
    main()
