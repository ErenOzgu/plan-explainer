import json
from pathlib import Path

from plan_explainer import report
from plan_explainer.analysis import Waived, analyse
from plan_explainer.config import Config, Waiver
from plan_explainer.llm import Narrative, summarise
from plan_explainer.model import parse

from .builders import load, plan_json, rc

REAL = Path(__file__).parent / "real"


def rendered(a, **kw):
    return report.markdown(a, summarise(a), **kw)


def test_the_markdown_has_the_headline_the_table_and_the_details(webshop):
    md = rendered(webshop)
    assert md.startswith("## Terraform plan: 6 to add, 4 to change, 1 to replace, 2 to destroy")
    assert (
        "| HIGH | open-ingress | `google_compute_firewall.debug_ssh` | SSH (22) open to the internet |" in md
    )
    assert (
        "**HIGH · data-loss** · `google_sql_database_instance.orders` · will be destroyed and created again"
        in md
    )
    assert "| replace | `google_sql_database_instance.orders` | forced by region |" in md
    assert "| destroy | `google_compute_disk.old_data` | it is no longer in the configuration |" in md
    assert "<details><summary>Argument changes</summary>" in md and md.count("</details>") == 1
    assert '`machine_type: "e2-small" → "e2-medium"`' in md
    assert "Summary written by the rules." in md


def test_changes_are_grouped_by_what_they_do_with_the_riskiest_first(webshop):
    rows = [
        ln.split("|")[1].strip()
        for ln in rendered(webshop).split("### Changes")[1].splitlines()
        if ln.startswith("| ") and "---" not in ln
    ][1:]
    assert rows == sorted(rows, key=["replace", "destroy", "change", "add"].index)


def test_the_output_does_not_depend_on_the_order_of_the_input():
    changes = [
        rc(
            "google_compute_firewall",
            "b",
            after={"source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["22"]}]},
        ),
        rc("google_compute_disk", "a", ("delete",), before={}),
        rc("google_dns_record_set", "c", ("update",), before={"ttl": 1}, after={"ttl": 2}),
    ]
    out = [
        report.markdown(a, summarise(a)) for a in (analyse(load(*changes)), analyse(load(*reversed(changes))))
    ]
    assert out[0] == out[1]
    j = [
        report.render_json(a, summarise(a))
        for a in (analyse(load(*changes)), analyse(load(*reversed(changes))))
    ]
    assert j[0] == j[1]


def test_text_and_json_formats(webshop):
    n = summarise(webshop)
    text = report.text(webshop, n)
    assert text.startswith("Plan: 6 to add, 4 to change, 1 to replace, 2 to destroy")
    assert "HIGH   open-ingress" in text and "google_compute_firewall.debug_ssh" in text
    data = json.loads(report.render_json(webshop, n))
    assert data["schema_version"] == 1
    assert data["plan"]["counts"] == {"add": 6, "change": 4, "replace": 1, "destroy": 2}
    assert [f["severity"] for f in data["findings"]].count("high") == 5
    assert {c["action"] for c in data["changes"]} == {"replace", "delete", "update", "create"}
    sql = next(c for c in data["changes"] if c["address"] == "google_sql_database_instance.orders")
    assert sql["replace_paths"] == ["region"] and sql["reason"] == "replace_because_cannot_update"
    assert data["summary"]["source"] == "rules"


def test_a_plan_without_findings_says_what_that_does_and_does_not_mean(tidy):
    md = rendered(tidy)
    assert "### Findings" in md and "not a review" in md and "### Look at first" not in md


def test_an_empty_plan():
    a = analyse(load())
    assert report.headline(a) == "no changes"
    assert "### Changes" not in rendered(a)


def test_values_from_the_plan_cannot_inject_markup_or_pings():
    import re

    hostile = "</details><img src=x onerror=alert(1)> @everyone | a\nb `c`"
    a = analyse(
        load(rc("google_dns_record_set", "x", ("update",), before={"name": "old"}, after={"name": hostile}))
    )
    md = rendered(a)
    outside = re.sub(r"`[^`\n]*`", "``", md)  # what a markdown renderer would treat as markup
    assert "<img" not in outside and outside.count("</details>") == 1
    assert "@everyone" not in outside


def test_free_text_values_are_escaped_outside_code_spans():
    import re

    a = analyse(
        load(
            rc(
                "google_project_iam_member",
                "x",
                after={"role": "roles/owner", "member": "user:<b>@everyone</b>"},
            )
        )
    )
    outside = re.sub(r"`[^`\n]*`", "``", rendered(a))
    assert "<b>" not in outside and "&lt;b&gt;" in outside
    assert "@everyone" not in outside


def test_a_finding_title_with_markup_is_escaped_in_the_table():
    from plan_explainer.report import md_cell, md_code, md_text

    assert md_cell("a|b\nc") == "a\\|b c"
    assert md_code("a`b|c") == "a'b\\|c"
    assert md_text("<b>@name</b>") == "&lt;b&gt;@​name&lt;/b&gt;"
    assert md_text("me@example.com") == "me@example.com"


def test_no_values_mode_names_arguments_and_nothing_else(webshop):
    md = rendered(webshop, values=False)
    assert "machine_type: changes" in md
    assert "e2-small" not in md and "34.89.0.20" not in md
    text = report.text(webshop, summarise(webshop), values=False)
    assert "e2-small" not in text and "machine_type: changes" in text
    data = json.loads(report.render_json(webshop, summarise(webshop), values=False))
    assert "e2-small" not in json.dumps(data["changes"])


def test_sensitive_values_never_appear_in_any_format():
    a = analyse(parse((REAL / "structure.json").read_text()))
    n = summarise(a)
    for out in (report.markdown(a, n), report.text(a, n), report.render_json(a, n)):
        assert "hunter2" not in out
    assert "(sensitive value changed)" in report.markdown(a, n)


def test_marked_sensitive_values_in_the_example_are_hidden(webshop):
    n = summarise(webshop)
    for out in (report.markdown(webshop, n), report.text(webshop, n), report.render_json(webshop, n)):
        assert "old-value" not in out and "new-value" not in out
    assert "secret_data: (sensitive value changed)" in report.markdown(webshop, n)


def test_many_changed_arguments_are_cut_and_counted():
    before = {f"k{i:02}": i for i in range(20)}
    after = {f"k{i:02}": i + 1 for i in range(20)}
    md = rendered(analyse(load(rc("google_x", "big", ("update",), before=before, after=after))))
    assert "- … 8 more" in md


def test_outputs_waivers_drift_and_notes():
    outputs = {"url": {"actions": ["create"], "before": None, "after": "x", "after_sensitive": False}}
    drift = [rc("google_compute_instance", "vm", ("update",), before={"a": 1}, after={"a": 2})]
    ssh = rc(
        "google_compute_firewall",
        "iap",
        after={"source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["22"]}]},
    )
    cfg = Config(
        waivers=(
            Waiver("open-ingress", "google_compute_firewall.iap", "IAP range"),
            Waiver("data-loss", "x", "stale"),
        )
    )
    a = analyse(parse(json.dumps(plan_json(ssh, outputs=outputs, drift=drift))), cfg)
    md = rendered(a)
    assert "- `url`: create" in md
    assert "Waived open-ingress on google_compute_firewall.iap: IAP range" in md
    assert "The waiver for data-loss on x matched nothing" in md
    assert "Changed outside Terraform since the last apply: google_compute_instance.vm" in md
    assert isinstance(a.waived[0], Waived)


def test_the_narrative_note_says_who_wrote_the_summary(webshop):
    model = Narrative("text", "model", "m-1")
    assert report.narrative_note(model) == "Summary written by m-1 and checked against the findings."
    rejected = Narrative(
        "rules text", "rules", "m-1", ["the figure 7 is not in the facts"], rejected_text="bad"
    )
    note = report.narrative_note(rejected)
    assert (
        "was rejected (the figure 7 is not in the facts)" in note and "replaced by the rules' summary" in note
    )
    assert "could not be used (boom)" in report.narrative_note(Narrative("t", "rules", "m", error="boom"))
    data = json.loads(report.render_json(webshop, rejected))
    assert data["summary"]["rejected_text"] == "bad" and data["summary"]["problems"]
