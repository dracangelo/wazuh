from pathlib import Path

from validator.rules_lint import lint_dir

ROOT = Path(__file__).resolve().parents[2]


def test_shipped_rules_are_clean():
    rep = lint_dir(ROOT / "rules" / "wazuh")
    assert not rep.issues, [str(i) for i in rep.issues]
    assert len(rep.rules) >= 60 and {5715, 31100} <= rep.external_refs


def _lint(tmp_path, xml):
    (tmp_path / "x.xml").write_text(xml)
    return [i.message for i in lint_dir(tmp_path).issues]


def test_detects_problems(tmp_path):
    msgs = _lint(tmp_path, """<group name="t">
      <rule id="100001" level="5"><description>a</description></rule>
      <rule id="100001" level="5"><description>dup</description></rule>
      <rule id="100002" level="20"><description>lvl</description></rule>
      <rule id="100003" level="5"><if_sid>100999</if_sid><description>orphan</description></rule>
      <rule id="100004" level="5"><regex type="pcre2">(unclosed</regex><description>bad</description></rule>
      <rule id="5" level="5"><description>range</description></rule>
      <rule id="100005" level="5" frequency="3"><description>f</description></rule>
    </group>""")
    joined = " | ".join(msgs)
    for needle in ("duplicate", "level must be", "not defined in this repo", "does not compile",
                   "outside custom range", "frequency requires timeframe"):
        assert needle in joined, needle


def test_malformed_xml(tmp_path):
    assert any("not well-formed" in m for m in _lint(tmp_path, "<!-- bad -- comment --><group/>"))
