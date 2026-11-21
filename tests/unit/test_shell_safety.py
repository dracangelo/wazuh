"""Tests for custom-simulations/lib/dv_safety.sh: ownership tracking and idempotent cleanup."""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "custom-simulations" / "lib" / "dv_safety.sh"


def run_bash(tmp_path, body):
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "DV_EXEC_ID": "dvtest0001",
        "DV_TEST_ID": "unit",
        "DV_MANIFEST": str(tmp_path / "manifest.list"),
    }
    script = f'set -u\n. "{LIB}"\n{body}\n'
    return subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env,
                          capture_output=True, text=True, check=False)


def test_preexisting_file_is_never_overwritten_or_removed(tmp_path):
    pre = tmp_path / "existing.txt"
    pre.write_text("keep", encoding="utf-8")
    p = run_bash(tmp_path, f'''
if dv_own_file "{pre}" "new"; then echo TOOK; fi
dv_cleanup; echo "cleanup=$?"
cat "{pre}"
''')
    assert p.returncode == 0, p.stderr
    assert "TOOK" not in p.stdout
    assert "cleanup=0" in p.stdout
    assert pre.read_text(encoding="utf-8") == "keep"


def test_created_resources_are_removed_and_cleanup_is_idempotent(tmp_path):
    p = run_bash(tmp_path, '''
d="$(dv_tmpdir)" || exit 1
f="$d/created.txt"
dv_own_file "$f" "x" || exit 1
dv_cleanup; echo "first=$?"
dv_cleanup; echo "second=$?"
[ -e "$d" ] && echo LEAK
echo done
''')
    assert p.returncode == 0, p.stderr
    assert "first=0" in p.stdout
    assert "second=0" in p.stdout
    assert "LEAK" not in p.stdout
    assert not (tmp_path / "manifest.list").exists()


def test_cleanup_runs_when_the_script_fails(tmp_path):
    target = tmp_path / "leftover.txt"
    p = run_bash(tmp_path, f'dv_own_file "{target}" "x" || exit 1\nexit 5')
    assert p.returncode == 5
    assert not target.exists()
    assert not (tmp_path / "manifest.list").exists()


def test_cleanup_failure_is_reported(tmp_path):
    # A path that cannot be removed (a non-empty directory tracked as a file) must be visible.
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "child").write_text("x", encoding="utf-8")
    p = run_bash(tmp_path, f'printf "%s\\n" "file:{locked}" >> "$DV_MANIFEST"\ndv_cleanup; echo "rc=$?"')
    assert "CLEANUP FAILED" in p.stderr
    assert "rc=1" in p.stdout
