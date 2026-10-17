"""Reading ``terraform show -json`` (Terraform and OpenTofu): the parts of a plan this tool uses."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .values import UNKNOWN, AttrChange, attr_changes, raw

KINDS = ("create", "update", "delete", "replace", "read", "no-op", "forget")

REASONS = {
    "replace_because_cannot_update": "a changed argument cannot be updated in place",
    "replace_because_tainted": "it is marked as tainted",
    "replace_by_request": "a replacement was requested (-replace)",
    "replace_by_triggers": "a replace_triggered_by reference changed",
    "delete_because_no_resource_config": "it is no longer in the configuration",
    "delete_because_no_module": "its module is no longer in the configuration",
    "delete_because_wrong_repetition": "it switched between count and for_each (or neither)",
    "delete_because_count_index": "count no longer reaches this index",
    "delete_because_each_key": "for_each no longer has this key",
    "read_because_config_unknown": "its configuration is not known until apply",
    "read_because_dependency_pending": "it depends on something that changes in this plan",
}


class PlanError(Exception):
    """The input is not a plan this tool can read."""


def kind_of(actions: tuple[str, ...]) -> str:
    if actions in (("delete", "create"), ("create", "delete")):
        return "replace"
    if len(actions) == 1 and actions[0] in KINDS:
        return actions[0]
    return "other"


@dataclass(frozen=True)
class Change:
    address: str
    module: str
    type: str
    name: str
    index: str | int | None
    provider: str
    mode: str
    actions: tuple[str, ...]
    kind: str
    before: Any
    after: Any
    before_sensitive: Any
    after_sensitive: Any
    after_unknown: Any
    replace_paths: tuple[str, ...]
    reason: str | None

    @property
    def create_before_destroy(self) -> bool:
        return self.actions == ("create", "delete")

    @property
    def base_address(self) -> str:
        """The address without a trailing [index] or ["key"]."""
        return self.address.rsplit("[", 1)[0] if self.address.endswith("]") else self.address

    @property
    def live(self) -> Any:
        """The planned value, or the current one for a delete."""
        return self.after if self.after is not None else self.before

    def after_values(self, *keys: str) -> list[Any]:
        return raw(self.after, *keys) if isinstance(self.after, dict) else []

    def before_values(self, *keys: str) -> list[Any]:
        return raw(self.before, *keys) if isinstance(self.before, dict) else []

    def attr_changes(self) -> list[AttrChange]:
        if self.kind not in ("update", "replace"):
            return []
        changes = attr_changes(
            self.before, self.after, self.before_sensitive, self.after_sensitive, self.after_unknown
        )
        # a replacement always gives the resource a new, unknown id; that says nothing
        return [c for c in changes if not (c.path == "id" and c.after is UNKNOWN)]

    @property
    def why(self) -> str | None:
        return REASONS.get(self.reason or "")


@dataclass(frozen=True)
class OutputChange:
    name: str
    kind: str
    sensitive: bool


@dataclass(frozen=True)
class Counts:
    add: int
    change: int
    replace: int
    destroy: int

    @property
    def total(self) -> int:
        return self.add + self.change + self.replace + self.destroy


@dataclass
class Plan:
    format_version: str
    tool_version: str
    changes: list[Change]
    outputs: list[OutputChange] = field(default_factory=list)
    drift: list[str] = field(default_factory=list)
    errored: bool = False
    notes: list[str] = field(default_factory=list)

    def counts(self) -> Counts:
        n = {k: 0 for k in KINDS}
        for c in self.changes:
            if c.mode == "managed":
                n[c.kind] = n.get(c.kind, 0) + 1
        return Counts(n["create"], n["update"], n["replace"], n["delete"])

    def acted(self) -> list[Change]:
        """Managed resources the plan will create, change, replace or destroy."""
        return [
            c
            for c in self.changes
            if c.mode == "managed" and c.kind in ("create", "update", "replace", "delete")
        ]

    def addresses(self) -> set[str]:
        return {c.address for c in self.changes} | {c.base_address for c in self.changes}


def _short_provider(name: str) -> str:
    return name.rstrip("/").rsplit("/", 1)[-1] if name else ""


def _change(rc: dict) -> Change:
    ch = rc.get("change") or {}
    actions = tuple(ch.get("actions") or ())
    paths = []
    for p in ch.get("replace_paths") or ():
        paths.append(".".join(f"[{x}]" if isinstance(x, int) else str(x) for x in p).replace(".[", "["))
    return Change(
        address=rc["address"],
        module=rc.get("module_address", ""),
        type=rc.get("type", ""),
        name=rc.get("name", ""),
        index=rc.get("index"),
        provider=_short_provider(rc.get("provider_name", "")),
        mode=rc.get("mode", "managed"),
        actions=actions,
        kind=kind_of(actions),
        before=ch.get("before"),
        after=ch.get("after"),
        before_sensitive=ch.get("before_sensitive", False),
        after_sensitive=ch.get("after_sensitive", False),
        after_unknown=ch.get("after_unknown", False),
        replace_paths=tuple(paths),
        reason=rc.get("action_reason"),
    )


def parse(text: str | bytes) -> Plan:
    if isinstance(text, bytes):
        if text[:2] == b"PK":
            raise PlanError(
                "this is a binary plan file; run `terraform show -json PLANFILE > plan.json` and pass that"
            )
        text = text.decode("utf-8", "replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PlanError(
            f"not JSON ({exc.msg} at line {exc.lineno}); expected `terraform show -json` output"
        ) from exc
    if not isinstance(data, dict) or "format_version" not in data:
        raise PlanError("this does not look like `terraform show -json` output of a plan (no format_version)")
    version = str(data["format_version"])
    if version.split(".")[0] != "1":
        raise PlanError(f"plan format {version} is not supported (this tool reads format 1.x)")
    if "resource_changes" not in data and "planned_values" not in data and "configuration" not in data:
        raise PlanError("this is JSON of a state or a configuration, not of a plan (no resource_changes)")

    plan = Plan(
        format_version=version,
        tool_version=str(data.get("terraform_version", "")),
        changes=[],
        errored=bool(data.get("errored")),
    )
    for rc in data.get("resource_changes") or []:
        ch = _change(rc)
        if ch.kind == "other":
            plan.notes.append(
                f"{ch.address}: actions {list(ch.actions)} are not known to this tool and are not counted"
            )
        plan.changes.append(ch)
    plan.changes.sort(key=lambda c: c.address)
    for name, oc in sorted((data.get("output_changes") or {}).items()):
        kind = kind_of(tuple(oc.get("actions") or ()))
        if kind not in ("no-op", "other"):
            plan.outputs.append(OutputChange(name, kind, bool(oc.get("after_sensitive") is True)))
    for d in data.get("resource_drift") or []:
        if kind_of(tuple((d.get("change") or {}).get("actions") or ())) not in ("no-op", "read", "other"):
            plan.drift.append(d.get("address", "?"))
    plan.drift.sort()
    if plan.errored:
        plan.notes.append("the plan is marked as errored; it may be incomplete")
    return plan
