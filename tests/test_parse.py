import json
from pathlib import Path

import pytest

from plan_explainer.model import PlanError, kind_of, parse

from .builders import load, plan_json, rc

REAL = Path(__file__).parent / "real"


def real(name):
    return parse((REAL / f"{name}.json").read_text())


def test_a_recorded_plan_has_every_kind_of_action():
    plan = real("lifecycle")
    kinds = {c.address: c.kind for c in plan.changes}
    assert kinds == {
        "terraform_data.brand_new": "create",
        "terraform_data.change_me": "update",
        "terraform_data.keep": "no-op",
        "terraform_data.remove_me": "delete",
        "terraform_data.replace_me": "replace",
    }
    c = plan.counts()
    assert (c.add, c.change, c.replace, c.destroy) == (1, 1, 1, 1)
    assert c.total == 4  # the no-op is not a change


def test_reasons_and_forcing_arguments_are_read():
    plan = {c.address: c for c in real("lifecycle").changes}
    assert plan["terraform_data.replace_me"].replace_paths == ("triggers_replace",)
    assert plan["terraform_data.replace_me"].why == "a changed argument cannot be updated in place"
    assert plan["terraform_data.remove_me"].why == "it is no longer in the configuration"


def test_create_before_destroy_modules_counts_and_keys():
    plan = {c.address: c for c in real("structure").changes}
    assert plan["terraform_data.cbd"].create_before_destroy
    assert plan["terraform_data.cbd"].actions == ("create", "delete")
    assert plan["module.m.terraform_data.inner"].module == "module.m"
    assert plan['terraform_data.keyed["b"]'].index == "b"
    assert plan["terraform_data.counted[1]"].index == 1
    assert plan['terraform_data.keyed["b"]'].base_address == "terraform_data.keyed"
    assert plan['terraform_data.keyed["b"]'].why == "for_each no longer has this key"


def test_outputs_and_the_provider_name():
    plan = real("lifecycle")
    assert [(o.name, o.kind, o.sensitive) for o in plan.outputs] == [("new_output", "create", False)]
    assert plan.changes[0].provider == "terraform"
    assert plan.tool_version == "1.8.5"


def test_both_orders_of_replace_are_a_replace():
    assert kind_of(("delete", "create")) == "replace"
    assert kind_of(("create", "delete")) == "replace"
    assert kind_of(("forget",)) == "forget"
    assert kind_of(("create", "forget")) == "other"


def test_unknown_actions_are_noted_not_fatal():
    plan = load(rc("google_x", "a", ["teleport"]))
    assert plan.changes[0].kind == "other"
    assert plan.counts().total == 0
    assert "teleport" in plan.notes[0]


def test_data_sources_are_not_counted_as_changes():
    r = rc("google_x", "d", ["read"])
    r["mode"] = "data"
    plan = load(r, rc("google_y", "m", ["create"], after={}))
    assert plan.counts().add == 1
    assert [c.address for c in plan.acted()] == ["google_y.m"]


def test_drift_is_collected():
    plan = load(drift=[rc("google_x", "a", ["update"], before={}, after={"k": 1})])
    assert plan.drift == ["google_x.a"]


def test_a_plan_with_no_changes():
    plan = parse(json.dumps({"format_version": "1.2", "terraform_version": "1.9.0", "planned_values": {}}))
    assert plan.changes == [] and plan.counts().total == 0


def test_errored_plans_are_flagged():
    assert "errored" in load(errored=True).notes[0]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("{not json", "not JSON"),
        ("[]", "format_version"),
        ('{"a": 1}', "format_version"),
        ('{"format_version": "2.0", "resource_changes": []}', "not supported"),
        ('{"format_version": "1.0", "values": {"root_module": {}}}', "state or a configuration"),
    ],
)
def test_input_that_is_not_a_plan_gets_a_clear_message(text, message):
    with pytest.raises(PlanError, match=message):
        parse(text)


def test_a_binary_plan_file_is_recognised():
    with pytest.raises(PlanError, match="terraform show -json"):
        parse(b"PK\x03\x04 zipped plan")


def test_changed_arguments_show_before_and_after():
    plan = real("lifecycle")
    ch = {c.address: c for c in plan.changes}["terraform_data.change_me"]
    lines = [a.line() for a in ch.attr_changes()]
    assert 'input: "before" → "after"' in lines
    assert 'output: "before" → (known after apply)' in lines


def test_the_id_of_a_replaced_resource_is_not_listed():
    ch = {c.address: c for c in real("lifecycle").changes}["terraform_data.replace_me"]
    assert [a.path for a in ch.attr_changes()] == ["triggers_replace[0]"]


def test_sensitive_values_are_hidden_where_terraform_marks_them_and_where_the_name_gives_them_away():
    ch = {c.address: c for c in real("structure").changes}["module.m.terraform_data.inner"]
    text = "\n".join(a.line() for a in ch.attr_changes())
    assert "hunter2" not in text
    assert "input.token: (sensitive value changed)" in text
    # Terraform did not mark `output` as sensitive; the name `token` inside it is enough
    assert '"token": "(sensitive)"' in text


def test_sensitivity_masks_follow_lists_and_whole_values():
    r = rc(
        "x_y",
        "a",
        ["update"],
        before={"items": ["a", "b"], "blob": {"k": "old"}},
        after={"items": ["a", "c"], "blob": {"k": "new"}},
        before_sensitive={"items": [False, True], "blob": True},
        after_sensitive={"items": [False, True], "blob": True},
    )
    lines = [a.line() for a in load(r).changes[0].attr_changes()]
    assert lines == ["blob: (sensitive value changed)", "items[1]: (sensitive value changed)"]


def test_a_new_nested_block_is_listed_per_argument():
    r = rc("x_y", "a", ["update"], before={"t": []}, after={"t": [{"a": 1, "b": "x"}]})
    lines = [a.line() for a in load(r).changes[0].attr_changes()]
    assert lines == ["t[0].a: (none) → 1", 't[0].b: (none) → "x"']


def test_plan_json_builder_is_the_real_shape():
    data = plan_json(rc("google_x", "a", after={"k": 1}))
    assert {"format_version", "terraform_version", "resource_changes"} <= set(data)
