"""Markdown, plain text and JSON from an analysis. Same input, same bytes."""

from __future__ import annotations

import json
import re

from . import __version__
from .analysis import Analysis
from .llm import Narrative
from .model import Change
from .rules import Finding

ACTION_ORDER = {"replace": 0, "delete": 1, "update": 2, "create": 3}
ACTION_WORD = {"replace": "replace", "delete": "destroy", "update": "change", "create": "add"}
MAX_ATTRS = 12


MENTION = re.compile(r"(?<![\w.])@(?=\w)")


def md_text(text: object) -> str:
    """Free text from a rule or a model: keep backticks and line breaks, defuse HTML and @mentions."""
    return MENTION.sub("@\u200b", str(text).replace("<", "&lt;").replace(">", "&gt;"))


def md_cell(text: object) -> str:
    """Text for a table cell."""
    return md_text(re.sub(r"\s+", " ", str(text))).replace("|", "\\|")


def md_code(text: object) -> str:
    """Text for an inline code span (which cannot contain a backtick)."""
    return re.sub(r"\s+", " ", str(text)).replace("`", "'").replace("|", "\\|")


def headline(a: Analysis) -> str:
    c = a.plan.counts()
    parts = [
        f"{n} to {w}"
        for w, n in (("add", c.add), ("change", c.change), ("replace", c.replace), ("destroy", c.destroy))
        if n
    ]
    return ", ".join(parts) if parts else "no changes"


def _sorted_changes(a: Analysis) -> list[Change]:
    return sorted(a.plan.acted(), key=lambda c: (ACTION_ORDER[c.kind], c.address))


def _attr_lines(ch: Change, values: bool) -> list[str]:
    lines = []
    for ac in ch.attr_changes():
        lines.append(ac.line() if values else f"{ac.path}: changes")
    return lines


def _what(ch: Change, values: bool) -> str:
    if ch.kind == "replace":
        text = f"forced by {', '.join(ch.replace_paths)}" if ch.replace_paths else "replaced"
        if ch.create_before_destroy:
            text += "; the new one is created first"
    elif ch.kind == "delete":
        text = ch.why or "destroyed"
    elif ch.kind == "update":
        names = [ac.path for ac in ch.attr_changes()]
        text = (
            ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
            if names
            else "in place"
        )
    else:
        text = ""
    return text


def _finding_block(f: Finding) -> list[str]:
    where = "the plan as a whole" if f.address == "(plan)" else f"`{md_code(f.address)}`"
    out = [f"**{f.severity.upper()} · {f.rule}** · {where} · {md_text(f.title)}", "", md_text(f.detail)]
    if f.evidence:
        out += ["", "Evidence: " + "; ".join(f"`{md_code(e)}`" for e in f.evidence)]
    out += ["", f"What to do: {md_text(f.advice)}", ""]
    return out


def narrative_note(n: Narrative) -> str:
    if n.source == "model":
        return f"Summary written by {md_text(n.model)} and checked against the findings."
    if n.problems:
        return f"A summary written by {md_text(n.model)} was rejected ({md_text('; '.join(n.problems))}) and replaced by the rules' summary."
    if n.error:
        return f"The model could not be used ({md_text(n.error)}); this is the rules' summary."
    return "Summary written by the rules."


def markdown(a: Analysis, n: Narrative, values: bool = True) -> str:
    out = [
        f"## Terraform plan: {headline(a)}",
        "",
        md_text(n.text),
        "",
        f"<sub>{narrative_note(n)}</sub>",
        "",
    ]
    if a.findings:
        out += ["### Look at first", "", "| Severity | Rule | Resource | Finding |", "|---|---|---|---|"]
        for f in a.findings:
            res = "(plan)" if f.address == "(plan)" else f"`{md_code(f.address)}`"
            out.append(f"| {f.severity.upper()} | {f.rule} | {res} | {md_cell(f.title)} |")
        out += [""]
        for f in a.findings:
            out += _finding_block(f)
    else:
        out += [
            "### Findings",
            "",
            "None. The rules cover a fixed list of risks (`plan-explainer rules`); this is not a review.",
            "",
        ]
    changes = _sorted_changes(a)
    if changes:
        out += ["### Changes", "", "| Action | Resource | Detail |", "|---|---|---|"]
        for ch in changes:
            out.append(f"| {ACTION_WORD[ch.kind]} | `{md_code(ch.address)}` | {md_cell(_what(ch, values))} |")
        out += [""]
        detail = [(ch, _attr_lines(ch, values)) for ch in changes if ch.kind in ("update", "replace")]
        detail = [(ch, lines) for ch, lines in detail if lines]
        if detail:
            out += ["<details><summary>Argument changes</summary>", ""]
            for ch, lines in detail:
                out.append(f"`{md_code(ch.address)}`")
                out.append("")
                out += [f"- `{md_code(line)}`" for line in lines[:MAX_ATTRS]]
                if len(lines) > MAX_ATTRS:
                    out.append(f"- … {len(lines) - MAX_ATTRS} more")
                out.append("")
            out += ["</details>", ""]
    if a.plan.outputs:
        out += ["### Outputs", ""]
        out += [
            f"- `{md_code(o.name)}`: {o.kind}{' (sensitive)' if o.sensitive else ''}" for o in a.plan.outputs
        ]
        out += [""]
    notes = _notes(a)
    if notes:
        out += ["### Notes", ""] + [f"- {md_text(x)}" for x in notes] + [""]
    out += [
        f"<sub>plan-explainer {__version__} · Terraform/OpenTofu {md_text(a.plan.tool_version)} · plan format {md_text(a.plan.format_version)}</sub>",
        "",
    ]
    return "\n".join(out)


def _notes(a: Analysis) -> list[str]:
    notes = list(a.plan.notes)
    for w in a.waived:
        notes.append(f"Waived {w.finding.rule} on {w.finding.address}: {w.waiver.reason}")
    for w in a.unused_waivers:
        notes.append(f"The waiver for {w.rule} on {w.address} matched nothing and can be removed")
    if a.plan.drift:
        notes.append("Changed outside Terraform since the last apply: " + ", ".join(a.plan.drift))
    return notes


def text(a: Analysis, n: Narrative, values: bool = True) -> str:
    out = [f"Plan: {headline(a)}", "", n.text.replace("`", ""), f"({narrative_note(n)})", ""]
    if a.findings:
        out.append("Findings")
        for f in a.findings:
            res = "(plan)" if f.address == "(plan)" else f.address
            out.append(f"  {f.severity.upper():6} {f.rule:20} {res}")
            out.append(f"         {f.title}. {f.detail}".replace("`", ""))
            for e in f.evidence:
                out.append(f"         evidence: {e}")
            out.append(f"         to do: {f.advice}".replace("`", ""))
        out.append("")
    else:
        out += ["Findings: none (the rules cover a fixed list of risks; this is not a review)", ""]
    changes = _sorted_changes(a)
    if changes:
        out.append("Changes")
        for ch in changes:
            detail = _what(ch, values)
            out.append(f"  {ACTION_WORD[ch.kind]:8} {ch.address}" + (f"  ({detail})" if detail else ""))
            for line in _attr_lines(ch, values)[:MAX_ATTRS] if ch.kind in ("update", "replace") else []:
                out.append(f"             {line}")
        out.append("")
    notes = _notes(a)
    if notes:
        out.append("Notes")
        out += [f"  - {x}" for x in notes]
        out.append("")
    return "\n".join(out)


def as_dict(a: Analysis, n: Narrative, values: bool = True) -> dict:
    c = a.plan.counts()

    def finding(f: Finding) -> dict:
        return {
            "rule": f.rule,
            "severity": f.severity,
            "address": f.address,
            "title": f.title,
            "detail": f.detail,
            "advice": f.advice,
            "evidence": list(f.evidence),
        }

    return {
        "schema_version": 1,
        "tool": {"name": "plan-explainer", "version": __version__},
        "plan": {
            "terraform_version": a.plan.tool_version,
            "format_version": a.plan.format_version,
            "counts": {"add": c.add, "change": c.change, "replace": c.replace, "destroy": c.destroy},
            "errored": a.plan.errored,
        },
        "summary": {
            "text": n.text,
            "source": n.source,
            "model": n.model,
            "rejected_text": n.rejected_text,
            "problems": n.problems,
            "error": n.error,
        },
        "findings": [finding(f) for f in a.findings],
        "waived": [{**finding(w.finding), "reason": w.waiver.reason} for w in a.waived],
        "unused_waivers": [{"rule": w.rule, "address": w.address} for w in a.unused_waivers],
        "changes": [
            {
                "address": ch.address,
                "type": ch.type,
                "action": ch.kind,
                "reason": ch.reason,
                "replace_paths": list(ch.replace_paths),
                "create_before_destroy": ch.create_before_destroy,
                "arguments": _attr_lines(ch, values) if ch.kind in ("update", "replace") else [],
            }
            for ch in _sorted_changes(a)
        ],
        "outputs": [{"name": o.name, "action": o.kind, "sensitive": o.sensitive} for o in a.plan.outputs],
        "notes": _notes(a),
    }


def render_json(a: Analysis, n: Narrative, values: bool = True) -> str:
    return json.dumps(as_dict(a, n, values), indent=2, ensure_ascii=False) + "\n"
