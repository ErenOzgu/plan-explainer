import io
import json
import sys

import pytest

from plan_explainer.cli import main
from plan_explainer.rules import RULES

from .conftest import PLANS, ROOT

WEBSHOP = str(PLANS / "webshop.json")
TIDY = str(PLANS / "tidy.json")
GOOD = (
    "This plan adds 6 resources, changes 4, replaces 1 and destroys 2. Start with google_sql_database_instance.orders, "
    "google_compute_disk.old_data, google_compute_firewall.debug_ssh, google_project_iam_member.ci_deployer "
    "and google_storage_bucket_iam_member.assets_public."
)


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_explain_prints_a_report_and_exits_zero(capsys):
    code, out, err = run(capsys, "explain", WEBSHOP)
    assert code == 0 and out.startswith("Plan: 6 to add") and err == ""


def test_fail_on_sets_the_exit_code_by_severity(capsys):
    code, _, err = run(capsys, "explain", WEBSHOP, "--fail-on", "high")
    assert code == 3 and "5 finding(s) at high or above" in err
    assert run(capsys, "explain", WEBSHOP, "--fail-on", "low")[0] == 3
    assert run(capsys, "explain", TIDY, "--fail-on", "low")[0] == 0
    assert run(capsys, "explain", TIDY)[0] == 0


def test_a_waiver_in_the_config_lets_the_gate_pass(capsys, tmp_path):
    cfg = tmp_path / "c.toml"
    waivers = "".join(
        f'[[waive]]\nrule = "{r}"\naddress = "{a}"\nreason = "known"\n\n'
        for r, a in [
            ("data-loss", "*"),
            ("open-ingress", "google_compute_firewall.debug_ssh"),
            ("broad-role", "*"),
            ("public-policy", "*"),
        ]
    )
    cfg.write_text(waivers)
    code, out, _ = run(capsys, "explain", WEBSHOP, "-c", str(cfg), "--fail-on", "high")
    assert code == 0 and "Waived" in out


def test_formats_and_output_file(capsys, tmp_path):
    code, out, _ = run(capsys, "explain", WEBSHOP, "-f", "json")
    assert code == 0 and json.loads(out)["plan"]["counts"]["add"] == 6
    assert run(capsys, "explain", WEBSHOP, "-f", "md")[1].startswith("## Terraform plan")
    target = tmp_path / "report.md"
    code, out, _ = run(capsys, "explain", WEBSHOP, "-f", "md", "-o", str(target))
    assert code == 0 and out == "" and target.read_text().startswith("## Terraform plan")


def test_standard_input(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(open(TIDY, "rb").read())))
    code, out, _ = run(capsys, "explain", "-")
    assert code == 0 and out.startswith("Plan: 2 to add, 1 to change")


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        (None, "cannot read"),
        ("{bad", "not JSON"),
        ("[1]", "format_version"),
    ],
)
def test_bad_input_exits_one_with_a_message(capsys, tmp_path, setup, message):
    path = tmp_path / "x.json"
    if setup is not None:
        path.write_text(setup)
    code, out, err = run(capsys, "explain", str(path))
    assert code == 1 and out == "" and message in err


def test_a_bad_config_exits_one(capsys, tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text('[[waive]]\nrule = "open-ingress"\naddress = "x"\n')
    code, _, err = run(capsys, "explain", WEBSHOP, "-c", str(cfg))
    assert code == 1 and "'reason' is required" in err
    assert run(capsys, "explain", WEBSHOP, "-c", str(tmp_path / "missing.toml"))[0] == 1


def test_llm_needs_a_key(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    code, _, err = run(capsys, "explain", WEBSHOP, "--llm")
    assert code == 2 and "ANTHROPIC_API_KEY" in err


def test_llm_with_a_fake_server_uses_a_checked_text(capsys, monkeypatch, anthropic):
    server = anthropic(GOOD)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", server.url)
    code, out, err = run(capsys, "explain", WEBSHOP, "--llm", "-f", "json")
    assert code == 0 and err == ""
    assert json.loads(out)["summary"]["source"] == "model" and len(server.requests) == 1


def test_llm_text_that_fails_the_check_is_reported_and_replaced(capsys, monkeypatch, anthropic):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", anthropic("All of this looks fine.").url)
    code, out, err = run(capsys, "explain", WEBSHOP, "--llm", "-f", "json")
    data = json.loads(out)
    assert (
        code == 0
        and data["summary"]["source"] == "rules"
        and data["summary"]["rejected_text"] == "All of this looks fine."
    )
    assert "model summary not used" in err


def test_without_llm_no_request_is_made_even_with_a_key(capsys, monkeypatch, anthropic):
    server = anthropic(GOOD)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", server.url)
    run(capsys, "explain", WEBSHOP)
    assert server.requests == []


def test_github_step_summary(capsys, monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    summary.write_text("earlier\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    code, out, _ = run(capsys, "explain", WEBSHOP, "--github-summary")
    assert code == 0 and out.startswith("Plan:")
    text = summary.read_text()
    assert text.startswith("earlier\n## Terraform plan: 6 to add")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY")
    code, _, err = run(capsys, "explain", WEBSHOP, "--github-summary")
    assert code == 2 and "GITHUB_STEP_SUMMARY" in err


def test_annotations_use_the_workflow_command_syntax(capsys):
    code, out, err = run(capsys, "explain", WEBSHOP, "--annotate")
    lines = [ln for ln in err.splitlines() if ln.startswith("::")]
    assert code == 0 and len(lines) == 12 and "::" not in out
    assert sum(ln.startswith("::error ") for ln in lines) == 5
    assert sum(ln.startswith("::warning ") for ln in lines) == 4
    assert sum(ln.startswith("::notice ") for ln in lines) == 3
    first = next(ln for ln in lines if "debug_ssh" in ln)
    assert first.startswith(
        "::error title=open-ingress%3A google_compute_firewall.debug_ssh::HIGH SSH (22) open to the internet."
    )
    for ln in lines:
        title, _, message = ln[2:].partition("::")
        assert "\n" not in ln and "," not in title


def test_the_rules_command(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0 and len(out.strip().splitlines()) == len(RULES) == 15
    code, out, _ = run(capsys, "rules", "--markdown")
    assert out.startswith("| Rule | Severity |") and "| `open-ingress` |" in out


def test_version_and_usage(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and "plan-explainer 0.1.0" in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        main([])
    assert e.value.code == 2


def test_module_entry_point():
    import subprocess

    r = subprocess.run(
        [sys.executable, "-m", "plan_explainer", "rules"], capture_output=True, text=True, cwd=ROOT
    )
    assert r.returncode == 0 and "open-ingress" in r.stdout
