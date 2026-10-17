"""Plans in the real `terraform show -json` shape, built from a few lines."""

from __future__ import annotations

import json

from plan_explainer.config import Config
from plan_explainer.model import Plan, parse
from plan_explainer.rules import Finding, check_change

GOOGLE = "registry.terraform.io/hashicorp/google"
AWS = "registry.terraform.io/hashicorp/aws"


def rc(
    rtype: str,
    name: str,
    actions=("create",),
    before=None,
    after=None,
    *,
    module=None,
    index=None,
    reason=None,
    replace_paths=None,
    after_unknown=None,
    after_sensitive=None,
    before_sensitive=None,
    provider=None,
) -> dict:
    actions = list(actions)
    address = f"{rtype}.{name}"
    if index is not None:
        address += f'["{index}"]' if isinstance(index, str) else f"[{index}]"
    if module:
        address = f"{module}.{address}"
    change = {
        "actions": actions,
        "before": before,
        "after": after,
        "after_unknown": after_unknown if after_unknown is not None else {},
        "before_sensitive": before_sensitive if before_sensitive is not None else False,
        "after_sensitive": after_sensitive if after_sensitive is not None else {},
    }
    if replace_paths:
        change["replace_paths"] = replace_paths
    out = {
        "address": address,
        "mode": "managed",
        "type": rtype,
        "name": name,
        "provider_name": provider or (AWS if rtype.startswith("aws_") else GOOGLE),
        "change": change,
    }
    if module:
        out["module_address"] = module
    if index is not None:
        out["index"] = index
    if reason:
        out["action_reason"] = reason
    return out


def plan_json(*changes: dict, outputs=None, drift=None, errored=False) -> dict:
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.8",
        "planned_values": {"root_module": {}},
        "resource_changes": list(changes),
        "output_changes": outputs or {},
        "resource_drift": drift or [],
        "configuration": {},
        "errored": errored,
    }


def load(*changes: dict, **kw) -> Plan:
    return parse(json.dumps(plan_json(*changes, **kw)))


def findings(
    rtype: str, after=None, actions=("create",), before=None, cfg: Config | None = None, **kw
) -> list[Finding]:
    plan = load(rc(rtype, "x", actions, before=before, after=after, **kw))
    return check_change(plan.changes[0], cfg or Config())


def rule_ids(found: list[Finding]) -> list[str]:
    return [f.rule for f in found]
