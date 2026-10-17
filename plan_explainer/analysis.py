"""Run the rules over a plan, apply waivers, and write the summary the rules can stand behind."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from .config import Config, Waiver
from .model import Plan
from .rules import RANK, SEVERITIES, Finding, check_change, check_plan


@dataclass(frozen=True)
class Waived:
    finding: Finding
    waiver: Waiver


@dataclass
class Analysis:
    plan: Plan
    config: Config
    findings: list[Finding]
    waived: list[Waived] = field(default_factory=list)
    unused_waivers: list[Waiver] = field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        return {s: sum(1 for f in self.findings if f.severity == s) for s in SEVERITIES}

    def worst(self) -> str | None:
        return min((f.severity for f in self.findings), key=RANK.get, default=None)

    def at_least(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if RANK[f.severity] <= RANK[severity]]


def analyse(plan: Plan, config: Config | None = None) -> Analysis:
    cfg = config or Config()
    found: list[Finding] = []
    for ch in plan.changes:
        found.extend(check_change(ch, cfg))
    found.extend(check_plan(plan, cfg))
    found.sort(key=lambda f: (RANK[f.severity], f.address, f.rule))
    active: list[Finding] = []
    waived: list[Waived] = []
    used: set[int] = set()
    for f in found:
        hit = next(
            (
                (i, w)
                for i, w in enumerate(cfg.waivers)
                if w.rule == f.rule and fnmatchcase(f.address, w.address)
            ),
            None,
        )
        if hit:
            used.add(hit[0])
            waived.append(Waived(f, hit[1]))
        else:
            active.append(f)
    unused = [w for i, w in enumerate(cfg.waivers) if i not in used]
    return Analysis(plan, cfg, active, waived, unused)


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _join(parts: list[str]) -> str:
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def rules_summary(a: Analysis) -> str:
    """The summary the rules write: counts, then where to look. It passes its own checker."""
    c = a.plan.counts()
    verbs = [("creates", c.add), ("changes", c.change), ("replaces", c.replace), ("destroys", c.destroy)]
    parts = []
    for verb, n in verbs:
        if n:
            parts.append(f"{verb} {plural(n, 'resource')}" if not parts else f"{verb} {n}")
    text = "This plan changes nothing." if not parts else f"This plan {_join(parts)}."
    sev = a.by_severity()
    total = sum(sev.values())
    if total:
        counted = [f"{n} {s}" for s, n in sev.items() if n]
        text += f" The rules raised {plural(total, 'finding')}: {_join(counted)}."
        worst = a.worst()
        top = [f for f in a.findings if f.severity == worst]
        names = []
        for f in top[:5]:
            names.append(
                f"`{f.address}` ({f.rule})" if f.address != "(plan)" else f"the plan as a whole ({f.rule})"
            )
        text += f" Start with {_join(names)}."
        if len(top) > 5:
            text += " More findings of the same severity follow in the list."
    else:
        text += (
            " The rules raised no findings. They cover a fixed list of risks (`plan-explainer rules`), "
            "so that is not the same as a review."
        )
    if a.waived:
        n = len(a.waived)
        text += f" {plural(n, 'finding')} {'was' if n == 1 else 'were'} waived in the configuration."
    return text
