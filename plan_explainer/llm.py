"""An optional model-written summary, and the checks it has to pass.

The model gets the findings and the list of changed resources: addresses, actions, rule titles, and the
names (never the values) of the arguments that force a replacement. It writes a few sentences. Those are
accepted only if they pass every check in ``check_text``; otherwise the rules' own summary is used.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .analysis import Analysis, rules_summary

API_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_LISTED = 80
MAX_CHARS = 1200

SYSTEM = (
    "You write the short summary at the top of an infrastructure plan review. You are given the facts of one "
    "Terraform plan: counts, the resources that change, and findings from a rule engine. Write 3 to 5 plain "
    "sentences, no markdown, no lists. Say what the plan does, then what a reviewer should look at first. "
    "Rules: use only the facts you are given; copy every resource address exactly as written; mention every "
    "HIGH finding by its resource address; copy numbers exactly, as digits, and compute none; do not say "
    "anything is safe, fine, harmless or low-risk; do not guess at causes or intentions; do not mention "
    "resources that are not listed."
)

ADDRESS = re.compile(
    r"^(?:module\.[\w\-]+(?:\[[^\]]*\])?\.)*[a-z][a-z0-9]*_[a-z0-9_]+\.[\w\-]+(?:\[[^\]]*\])?$"
)
NUMBER = re.compile(r"(?<![\w.\-])\d+(?![\w\-]|\.\d)")
REASSURING = re.compile(
    r"\b(safe|safely|harmless|risk[- ]free|no risk|low[- ]risk|nothing (?:to worry|risky|dangerous)|"
    r"looks (?:fine|good)|no (?:concerns|issues|problems))\b",
    re.IGNORECASE,
)
DESTRUCTIVE = re.compile(r"\b(destroy\w*|delet\w+|remov\w+)\b", re.IGNORECASE)


class ModelError(Exception):
    """The model could not be reached or returned nothing usable."""


def facts_for_model(a: Analysis) -> str:
    c = a.plan.counts()
    lines = [
        f"Plan: {c.add} to add, {c.change} to change, {c.replace} to replace, {c.destroy} to destroy.",
        "",
        "Resources that change:",
    ]
    acted = a.plan.acted()
    for ch in acted[:MAX_LISTED]:
        extra = (
            f" (forced by {', '.join(ch.replace_paths)})" if ch.kind == "replace" and ch.replace_paths else ""
        )
        lines.append(f"- {ch.address}: {ch.kind}{extra}")
    if len(acted) > MAX_LISTED:
        lines.append(f"- ... and {len(acted) - MAX_LISTED} more not listed")
    sev = a.by_severity()
    lines += [
        "",
        f"Findings from the rules: {sum(sev.values())} ({sev['high']} high, {sev['medium']} medium, {sev['low']} low), "
        "highest severity first:",
    ]
    if not a.findings:
        lines.append("- none")
    for f in a.findings:
        where = f.address if f.address != "(plan)" else "the whole plan"
        lines.append(f"- {f.severity.upper()} {f.rule} on {where}: {f.title}")
    if a.waived:
        lines += ["", f"Waived in the configuration: {len(a.waived)} finding(s)."]
    return "\n".join(lines)


def _mask_addresses(text: str, known: set[str]) -> str:
    """The text with every resource address replaced by a placeholder, so digits inside names are not figures."""
    out = []
    for raw_tok in re.split(r"(\s+)", text.replace("`", " ")):
        tok = raw_tok.strip(".,;:)(")
        out.append("ADDR" if tok in known or ADDRESS.match(tok) else raw_tok)
    return "".join(out)


def check_text(text: str, a: Analysis, prompt_facts: str | None = None) -> list[str]:
    """Why this summary cannot be used; an empty list means it passed."""
    problems: list[str] = []
    known = a.plan.addresses()
    if not text.strip():
        return ["the text is empty"]
    if len(text) > MAX_CHARS:
        problems.append(f"it is longer than {MAX_CHARS} characters")
    for raw_tok in re.split(r"\s+", text.replace("`", " ")):
        tok = raw_tok.strip(".,;:)(")
        if tok not in known and ADDRESS.match(tok):
            problems.append(f"it mentions {tok}, which is not in the plan")
    facts = prompt_facts if prompt_facts is not None else facts_for_model(a)
    allowed = set(NUMBER.findall(_mask_addresses(facts, known)))
    for n in dict.fromkeys(NUMBER.findall(_mask_addresses(text, known))):
        if n not in allowed:
            problems.append(f"the figure {n} is not in the facts")
    for f in a.findings:
        if f.severity == "high" and f.address != "(plan)":
            base = f.address.rsplit("[", 1)[0] if f.address.endswith("]") else f.address
            if f.address not in text and base not in text:
                problems.append(f"it does not mention the high-severity finding on {f.address}")
    m = REASSURING.search(text)
    if m:
        problems.append(
            f"it reassures ({m.group(0)!r}), which a rule engine with a fixed list cannot promise"
        )
    c = a.plan.counts()
    if c.destroy + c.replace == 0:
        m = DESTRUCTIVE.search(text)
        if m:
            problems.append(
                f"it talks about destroying or removing ({m.group(0)!r}), but nothing is destroyed or replaced"
            )
    return list(dict.fromkeys(problems))


def call_model(
    prompt: str,
    api_key: str,
    model: str | None = None,
    base_url: str | None = None,
    max_tokens: int = 500,
    timeout: float = 60,
) -> str:
    base = (base_url or os.environ.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com").rstrip("/")
    body = json.dumps(
        {
            "model": model or os.environ.get("PLAN_EXPLAINER_MODEL") or DEFAULT_MODEL,
            "max_tokens": max_tokens,
            "system": SYSTEM,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode()
    req = urllib.request.Request(
        base + "/v1/messages",
        data=body,
        headers={
            "x-api-key": api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
            "user-agent": "plan-explainer",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as exc:
        raise ModelError(f"API returned {exc.code}: {exc.read(300).decode('utf-8', 'replace')}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ModelError(f"cannot reach the API: {exc}") from exc
    text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()
    if not text:
        raise ModelError("the API returned no text")
    return text


@dataclass
class Narrative:
    text: str
    source: str  # "rules" | "model"
    model: str = ""
    problems: list[str] = field(default_factory=list)
    rejected_text: str = ""
    error: str = ""


def summarise(
    a: Analysis, api_key: str | None = None, model: str | None = None, base_url: str | None = None
) -> Narrative:
    """The model's summary if it passes every check; otherwise the rules' summary, and why."""
    fallback = rules_summary(a)
    if not api_key:
        return Narrative(fallback, "rules")
    used = model or os.environ.get("PLAN_EXPLAINER_MODEL") or DEFAULT_MODEL
    facts = facts_for_model(a)
    try:
        text = call_model(facts, api_key, model=used, base_url=base_url)
    except ModelError as exc:
        return Narrative(fallback, "rules", used, error=str(exc))
    problems = check_text(text, a, facts)
    if problems:
        return Narrative(fallback, "rules", used, problems, rejected_text=text)
    return Narrative(text, "model", used)
