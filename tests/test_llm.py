import json

import pytest

from plan_explainer.analysis import analyse, rules_summary
from plan_explainer.llm import ModelError, call_model, check_text, facts_for_model, summarise
from plan_explainer.model import parse

from .builders import load, plan_json, rc

HIGHS = [
    "google_compute_disk.old_data",
    "google_compute_firewall.debug_ssh",
    "google_project_iam_member.ci_deployer",
    "google_sql_database_instance.orders",
    "google_storage_bucket_iam_member.assets_public",
]
GOOD = (
    "This plan adds 6 resources, changes 4, replaces 1 and destroys 2. Start with "
    "`google_sql_database_instance.orders`, which is destroyed and created again, and `google_compute_disk.old_data`, "
    "then `google_compute_firewall.debug_ssh` (SSH (22) open to the internet), "
    "`google_project_iam_member.ci_deployer` and `google_storage_bucket_iam_member.assets_public`."
)


def test_a_good_text_passes(webshop):
    assert check_text(GOOD, webshop) == []


def test_an_address_that_is_not_in_the_plan_is_found(webshop):
    problems = check_text(GOOD + " Also look at google_compute_instance.database.", webshop)
    assert problems == ["it mentions google_compute_instance.database, which is not in the plan"]


def test_a_figure_that_is_not_in_the_facts_is_found(webshop):
    problems = check_text(GOOD.replace("adds 6", "adds 7"), webshop)
    assert problems == ["the figure 7 is not in the facts"]


def test_figures_from_finding_titles_are_allowed_and_digits_in_names_are_not_figures(webshop):
    assert check_text(GOOD + " Port 22 is the one to look at.", webshop) == []
    a = analyse(load(rc("google_compute_instance", "web_2", ("delete",), before={})))
    assert check_text("It destroys 1 resource, `google_compute_instance.web_2`.", a) == []
    assert check_text("It destroys 2 resources, google_compute_instance.web_2.", a) == [
        "the figure 2 is not in the facts"
    ]


def test_every_high_finding_has_to_be_mentioned(webshop):
    problems = check_text(GOOD.replace("`google_compute_disk.old_data`", "the disk"), webshop)
    assert problems == ["it does not mention the high-severity finding on google_compute_disk.old_data"]


def test_a_text_that_only_names_the_resource_without_its_index_counts_as_mentioning_it():
    a = analyse(
        load(
            rc(
                "google_compute_firewall",
                "web",
                index="a",
                after={"source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["22"]}]},
            )
        )
    )
    assert check_text("It adds 1 resource; look at google_compute_firewall.web first.", a) == []


@pytest.mark.parametrize(
    "phrase",
    [
        "The rest looks fine.",
        "This is safe to apply.",
        "It is low-risk.",
        "There are no concerns.",
        "Nothing risky here.",
    ],
)
def test_reassurance_is_rejected(webshop, phrase):
    problems = check_text(GOOD + " " + phrase, webshop)
    assert len(problems) == 1 and problems[0].startswith("it reassures")


def test_unsafe_is_not_reassurance(webshop):
    assert check_text(GOOD + " The firewall rule is unsafe.", webshop) == []


def test_destroy_talk_when_nothing_is_destroyed_is_rejected(tidy):
    ok = "This plan adds 2 resources and changes 1."
    assert check_text(ok, tidy) == []
    problems = check_text("This plan adds 2 resources and removes 1.", tidy)
    assert problems[0].startswith("it talks about destroying or removing")


def test_empty_and_overlong_text(webshop):
    assert check_text("  ", webshop) == ["the text is empty"]
    assert "longer than 1200" in check_text(GOOD + " x" * 700, webshop)[0]


def test_the_model_is_given_addresses_actions_and_titles_and_nothing_else(webshop):
    facts = facts_for_model(webshop)
    assert "google_sql_database_instance.orders: replace (forced by region)" in facts
    assert "HIGH open-ingress on google_compute_firewall.debug_ssh: SSH (22) open to the internet" in facts
    for value in ("0.0.0.0/0", "34.89.0.10", "old-value", "new-value", "europe-west1", "serviceAccount"):
        assert value not in facts


def test_a_checked_model_text_is_used(anthropic, webshop):
    server = anthropic(GOOD)
    n = summarise(webshop, "key-123", base_url=server.url)
    assert (n.source, n.text, n.problems) == ("model", GOOD, [])
    req = server.requests[0]
    assert req["path"] == "/v1/messages" and req["headers"]["x-api-key"] == "key-123"
    body = json.loads(req["body"])
    assert (
        body["model"] == "claude-sonnet-5-5"
        and "google_compute_disk.old_data" in body["messages"][0]["content"]
    )
    assert "HIGH finding" in body["system"]


def test_the_request_never_carries_a_value_from_the_plan(anthropic, webshop):
    server = anthropic(GOOD)
    summarise(webshop, "k", base_url=server.url)
    raw = server.requests[0]["body"].decode()
    for value in ("0.0.0.0/0", "34.89.0.10", "old-value", "new-value", "e2-medium", "ci-deployer@"):
        assert value not in raw


def test_a_rejected_text_is_replaced_by_the_rules_summary_and_kept_for_inspection(anthropic, webshop):
    bad = GOOD.replace("destroys 2", "destroys 20")
    n = summarise(webshop, "k", base_url=anthropic(bad).url)
    assert n.source == "rules" and n.text == rules_summary(webshop)
    assert n.rejected_text == bad and n.problems == ["the figure 20 is not in the facts"]


def test_an_api_error_falls_back_without_raising(anthropic, webshop):
    n = summarise(webshop, "k", base_url=anthropic(status=529).url)
    assert n.source == "rules" and "529" in n.error and n.text == rules_summary(webshop)


def test_an_unreachable_api_falls_back(webshop):
    n = summarise(webshop, "k", base_url="http://127.0.0.1:9")
    assert n.source == "rules" and "cannot reach the API" in n.error


def test_an_empty_reply_is_an_error(anthropic):
    with pytest.raises(ModelError, match="no text"):
        call_model("x", "k", base_url=anthropic("").url)


def test_without_a_key_no_request_is_made(anthropic, webshop):
    server = anthropic(GOOD)
    n = summarise(webshop, None, base_url=server.url)
    assert n.source == "rules" and server.requests == []


def test_the_model_name_can_come_from_the_environment(anthropic, webshop, monkeypatch):
    monkeypatch.setenv("PLAN_EXPLAINER_MODEL", "some-model")
    server = anthropic(GOOD)
    summarise(webshop, "k", base_url=server.url)
    assert json.loads(server.requests[0]["body"])["model"] == "some-model"


def test_long_plans_are_cut_in_the_prompt_and_the_cut_is_stated():
    changes = [rc("google_compute_firewall", f"f{i:03}", ("delete",), before={}) for i in range(95)]
    facts = facts_for_model(analyse(parse(json.dumps(plan_json(*changes)))))
    assert "- ... and 15 more not listed" in facts
    assert facts.count("\n- google_compute_firewall.f") == 80
