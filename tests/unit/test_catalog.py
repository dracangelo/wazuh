from pathlib import Path

from validator.orchestrator import load_catalog

ROOT = Path(__file__).resolve().parents[2]


def test_shipped_catalog_is_valid():
    assert len(load_catalog(ROOT / "test-catalog")) >= 5
    assert load_catalog(ROOT / "tests" / "regression")
