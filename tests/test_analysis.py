import pytest

from plan_explainer.analysis import analyse, rules_summary
from plan_explainer.config import Config, ConfigError, Waiver, parse
from plan_explainer.llm import check_text
from plan_explainer.rules import rule_ids

from .builders import load, rc

SSH = {
    "source_ranges": ["0.0.0.0/0"],
    "allow": [{"protocol": "tcp", "ports": ["22"]}],
}


def ssh_plan(*names):
    return load(*[rc("google_compute_firewall", n, after=SSH) for n in names])


def test_a_waiver_moves_the_finding_out_of_the_list_and_keeps_its_reason():
    cfg = Config(waivers=(Waiver("open-ingress", "google_compute_firewall.iap", "IAP TCP forwarding range"),))
    a = analyse(ssh_plan("iap", "other"), cfg)
    assert [f.address for f in a.findings] == ["google_compute_firewall.other"]
    assert [(w.finding.address, w.waiver.reason) for w in a.waived] == [
        ("google_compute_firewall.iap", "IAP TCP forwarding range")
    ]
    assert a.unused_waivers == []


def test_waivers_match_patterns_but_only_for_their_rule():
    cfg = Config(
        waivers=(Waiver("open-ingress", "google_compute_firewall.iap_*", "x"), Waiver("data-loss", "*", "y"))
    )
    a = analyse(ssh_plan("iap_a", "iap_b", "c"), cfg)
    assert [f.address for f in a.findings] == ["google_compute_firewall.c"]
    assert [w.rule for w in a.unused_waivers] == ["data-loss"]


def test_the_plan_wide_finding_can_be_waived_by_name():
    deletes = [rc("google_compute_firewall", f"f{i}", ("delete",), before={}) for i in range(10)]
    a = analyse(load(*deletes), Config(waivers=(Waiver("mass-destroy", "(plan)", "planned clean-up"),)))
    assert a.findings == [] and len(a.waived) == 1


def test_severity_helpers():
    a = analyse(ssh_plan("a"))
    assert a.worst() == "high" and a.by_severity() == {"high": 1, "medium": 0, "low": 0}
    assert len(a.at_least("high")) == 1 and len(a.at_least("low")) == 1
    assert analyse(load()).worst() is None


def test_the_rules_summary_for_the_example(webshop):
    text = rules_summary(webshop)
    assert text.startswith("This plan creates 6 resources, changes 4, replaces 1 and destroys 2.")
    assert "12 findings: 5 high, 4 medium and 3 low" in text
    for f in webshop.findings:
        if f.severity == "high":
            assert f.address in text


def test_the_rules_summary_for_a_plan_without_findings(tidy):
    text = rules_summary(tidy)
    assert "raised no findings" in text and "not the same as a review" in text


def test_an_empty_plan():
    assert rules_summary(analyse(load())).startswith("This plan changes nothing.")


def test_singulars():
    a = analyse(load(rc("google_compute_firewall", "a", after=SSH)))
    assert rules_summary(a).startswith("This plan creates 1 resource.")
    assert "1 finding: 1 high" in rules_summary(a)


def test_waived_findings_are_counted_in_the_summary():
    cfg = Config(waivers=(Waiver("open-ingress", "*", "ok"),))
    assert "1 finding was waived" in rules_summary(analyse(ssh_plan("a"), cfg))


@pytest.mark.parametrize("fixture", ["webshop", "tidy"])
def test_the_rules_summary_passes_its_own_check(request, fixture):
    a = request.getfixturevalue(fixture)
    assert check_text(rules_summary(a), a) == []


def test_the_rules_summary_passes_its_own_check_for_many_shapes():
    import itertools

    kinds = [
        rc("google_compute_firewall", "ssh", after=SSH),
        rc("google_compute_firewall", "old", ("delete",), before={}),
        rc(
            "google_sql_database_instance",
            "db",
            ("delete", "create"),
            before={},
            after={},
            replace_paths=[["region"]],
        ),
        rc("google_project_iam_member", "o", after={"role": "roles/owner", "member": "user:a@b.c"}),
        rc("google_compute_disk", "d1", ("delete",), before={}),
        rc("google_compute_instance", "vm", ("update",), before={"a": 1}, after={"a": 2}),
        rc("google_compute_firewall", "web2", index=2, after={"source_ranges": ["10.0.0.0/8"], "allow": []}),
    ]
    checked = 0
    for r in range(len(kinds) + 1):
        for combo in itertools.combinations(kinds, r):
            a = analyse(load(*combo))
            assert check_text(rules_summary(a), a) == [], [c["address"] for c in combo]
            checked += 1
    assert checked == 2 ** len(kinds)


# --- config ---------------------------------------------------------------------------------------------


def test_a_full_config():
    cfg = parse(
        """
stateful_types = ["acme_widget"]
mass_destroy = 4

[[waive]]
rule = "open-ingress"
address = "google_compute_firewall.iap"
reason = "  IAP range  "
""",
        rule_ids(),
    )
    assert cfg.stateful_types == {"acme_widget"} and cfg.mass_destroy == 4
    assert cfg.waivers == (Waiver("open-ingress", "google_compute_firewall.iap", "IAP range"),)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("this is = = not toml", "not valid TOML"),
        ("colour = 1", "unknown setting 'colour'"),
        ("stateful_types = 'x'", "stateful_types must be a list"),
        ("mass_destroy = 0", "mass_destroy must be"),
        ("mass_destroy = true", "mass_destroy must be"),
        ('[[waive]]\nrule = "open-ingress"\naddress = "x"', "'reason' is required \\(say why"),
        ('[[waive]]\nrule = "open-ingress"\naddress = "x"\nreason = " "', "'reason' is required"),
        ('[[waive]]\nrule = "nope"\naddress = "x"\nreason = "r"', "unknown rule 'nope'"),
        (
            '[[waive]]\nrule = "open-ingress"\naddress = "x"\nreason = "r"\nuntil = "2027"',
            "unknown key 'until'",
        ),
    ],
)
def test_config_errors_say_what_is_wrong(text, message):
    with pytest.raises(ConfigError, match=message):
        parse(text, rule_ids())
