"""Plans recorded from a real OpenTofu run (tests/real/record.sh). CI records them again with Terraform."""

import json
from pathlib import Path

import pytest

from plan_explainer import report
from plan_explainer.analysis import analyse, rules_summary
from plan_explainer.config import load as load_config
from plan_explainer.llm import check_text, summarise
from plan_explainer.model import parse
from plan_explainer.rules import rule_ids

REAL = Path(__file__).parent / "real"


@pytest.mark.parametrize("name", ["lifecycle", "structure"])
def test_every_report_format_works_on_a_real_plan(name):
    a = analyse(parse((REAL / f"{name}.json").read_text()))
    n = summarise(a)
    assert check_text(rules_summary(a), a) == []
    assert report.markdown(a, n) and report.text(a, n)
    assert json.loads(report.render_json(a, n))["plan"]["counts"]


def test_the_data_loss_rule_on_a_real_replace_and_a_real_destroy():
    cfg = load_config(REAL / "stateful.toml", rule_ids())
    a = analyse(parse((REAL / "structure.json").read_text()), cfg)
    got = sorted(f"{f.rule} {f.address}" for f in a.findings)
    assert got == (REAL / "expected-structure.txt").read_text().splitlines()
    cbd = next(f for f in a.findings if f.address == "terraform_data.cbd")
    assert "created first" in cbd.detail and "forced by triggers_replace" in cbd.detail
    gone = next(f for f in a.findings if f.address.endswith('["b"]'))
    assert "for_each no longer has this key" in gone.detail


def test_without_the_config_a_real_plan_of_unknown_resources_has_no_findings():
    assert analyse(parse((REAL / "structure.json").read_text())).findings == []
