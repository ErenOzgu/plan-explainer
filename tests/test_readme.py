from pathlib import Path

from plan_explainer.rules import RULES, rules_markdown

README = (Path(__file__).resolve().parent.parent / "README.md").read_text()


def test_the_rules_table_in_the_readme_is_what_the_tool_prints():
    table = README.split("<!-- rules:start -->\n")[1].split("\n<!-- rules:end -->")[0]
    assert table == rules_markdown()


def test_the_readme_counts_match_the_code():
    n = len(RULES)
    assert f"{n} rules, plain Python" in README
    assert f"none of these {n}" in README
    assert "all 128" in README  # 2 ** 7 combinations in test_analysis


def test_the_readme_example_report_is_the_committed_one():
    assert "examples/reports/webshop.md" in README
    assert (Path(__file__).resolve().parent.parent / "examples" / "reports" / "webshop.md").exists()
