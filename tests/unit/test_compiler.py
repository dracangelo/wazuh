"""Unit tests for the automatic Sigma-to-Wazuh compiler."""
import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess

ROOT_DIR = Path(__file__).resolve().parents[2]
COMPILER = ROOT_DIR / "scripts" / "compile_sigma.py"


def test_compile_linux_sigma_rule(tmp_path: Path):
    sigma_yaml = tmp_path / "test_linux.yml"
    sigma_yaml.write_text(
        """
title: Test Linux Reverse Shell
id: 11111111-2222-3333-4444-555555555555
status: test
description: Test detection description
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith:
      - '/nc'
    CommandLine|contains:
      - ' -e '
  condition: selection
level: high
tags:
  - attack.t1059.004
""",
        encoding="utf-8",
    )

    out_xml = tmp_path / "out_linux.xml"
    res = subprocess.run(
        [
            "python3",
            str(COMPILER),
            "--sigma",
            str(sigma_yaml),
            "--start-id",
            "100990",
            "--output",
            str(out_xml),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert out_xml.exists()

    tree = ET.parse(out_xml)
    root = tree.getroot()
    assert root.tag == "group"
    rule = root.find("rule")
    assert rule is not None
    assert rule.attrib["id"] == "100990"
    assert rule.attrib["level"] == "11"
    assert rule.find("if_sid").text == "100400"
    assert "Sigma: Test Linux Reverse Shell" in rule.find("description").text
    assert rule.find("mitre").find("id").text == "T1059.004"


def test_compile_windows_sigma_rule(tmp_path: Path):
    sigma_yaml = tmp_path / "test_win.yml"
    sigma_yaml.write_text(
        """
title: Test Windows Certutil
id: 22222222-3333-4444-5555-666666666666
status: test
description: Test windows certutil download
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains:
      - ' -urlcache '
  condition: selection
level: medium
tags:
  - attack.t1105
""",
        encoding="utf-8",
    )

    out_xml = tmp_path / "out_win.xml"
    res = subprocess.run(
        [
            "python3",
            str(COMPILER),
            "--sigma",
            str(sigma_yaml),
            "--start-id",
            "100995",
            "--output",
            str(out_xml),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert out_xml.exists()

    tree = ET.parse(out_xml)
    root = tree.getroot()
    rule = root.find("rule")
    assert rule is not None
    assert rule.attrib["id"] == "100995"
    assert rule.attrib["level"] == "8"
    assert rule.find("if_sid").text == "100712"
    assert rule.find("mitre").find("id").text == "T1105"

