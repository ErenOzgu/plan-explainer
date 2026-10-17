"""plan-explainer explain PLAN.json | plan-explainer rules"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, report
from .analysis import analyse
from .config import Config, ConfigError
from .config import load as load_config
from .llm import Narrative, summarise
from .model import PlanError, parse
from .rules import RULES, SEVERITIES, rule_ids, rules_markdown

OK, ERROR, USAGE, FINDINGS = 0, 1, 2, 3


def _annotation_escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _annotations(a) -> list[str]:  # noqa: ANN001
    level = {"high": "error", "medium": "warning", "low": "notice"}
    lines = []
    for f in a.findings:
        title = _annotation_escape(f"{f.rule}: {f.address}").replace(",", "%2C").replace(":", "%3A")
        lines.append(
            f"::{level[f.severity]} title={title}::{_annotation_escape(f.severity.upper() + ' ' + f.title + '. ' + f.advice)}"
        )
    return lines


def _read(arg: str) -> bytes:
    if arg == "-":
        return sys.stdin.buffer.read()
    try:
        return Path(arg).read_bytes()
    except OSError as exc:
        raise PlanError(f"cannot read {arg}: {exc.strerror}") from exc


def explain(args: argparse.Namespace) -> int:
    try:
        plan = parse(_read(args.plan))
        cfg: Config = load_config(args.config, rule_ids()) if args.config else Config()
    except (PlanError, ConfigError) as exc:
        print(f"plan-explainer: {exc}", file=sys.stderr)
        return ERROR
    a = analyse(plan, cfg)
    key = os.environ.get("ANTHROPIC_API_KEY")
    if args.llm and not key:
        print("plan-explainer: --llm needs ANTHROPIC_API_KEY in the environment", file=sys.stderr)
        return USAGE
    narrative: Narrative = summarise(a, key if args.llm else None, args.model)
    values = not args.no_values
    render = {"md": report.markdown, "text": report.text, "json": report.render_json}[args.format]
    body = render(a, narrative, values)
    if args.out:
        Path(args.out).write_text(body, encoding="utf-8")
    else:
        sys.stdout.write(body)
    if args.github_summary:
        target = os.environ.get("GITHUB_STEP_SUMMARY")
        if not target:
            print(
                "plan-explainer: --github-summary needs GITHUB_STEP_SUMMARY (it is set inside GitHub Actions)",
                file=sys.stderr,
            )
            return USAGE
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(report.markdown(a, narrative, values) + "\n")
    if args.annotate:
        for line in _annotations(a):
            print(line, file=sys.stderr)
    if narrative.source == "rules" and (narrative.problems or narrative.error):
        reason = "; ".join(narrative.problems) or narrative.error
        print(f"plan-explainer: model summary not used: {reason}", file=sys.stderr)
    if args.fail_on and a.at_least(args.fail_on):
        n = len(a.at_least(args.fail_on))
        print(f"plan-explainer: {n} finding(s) at {args.fail_on} or above", file=sys.stderr)
        return FINDINGS
    return OK


def list_rules(args: argparse.Namespace) -> int:
    if args.markdown:
        print(rules_markdown())
        return OK
    for r in sorted(RULES, key=lambda r: r.id):
        print(f"{r.id:22} {r.severity:20} {r.summary}")
    return OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="plan-explainer",
        description="Explain a Terraform or OpenTofu plan: what changes, and what deserves a second look.",
    )
    p.add_argument("--version", action="version", version=f"plan-explainer {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("explain", help="explain the output of `terraform show -json PLANFILE`")
    e.add_argument("plan", help="the JSON file, or - for standard input")
    e.add_argument("-c", "--config", help="a TOML file: extra stateful types, waivers with reasons")
    e.add_argument("-f", "--format", choices=["text", "md", "json"], default="text")
    e.add_argument("-o", "--out", help="write the report to this file instead of standard output")
    e.add_argument(
        "--fail-on", choices=SEVERITIES, help="exit with 3 if a finding is at this severity or above"
    )
    e.add_argument(
        "--llm",
        action="store_true",
        help="let a model write the summary (needs ANTHROPIC_API_KEY); it is checked",
    )
    e.add_argument("--model", help="model name (default: PLAN_EXPLAINER_MODEL or claude-sonnet-5-5)")
    e.add_argument(
        "--no-values", action="store_true", help="show the names of changed arguments, never their values"
    )
    e.add_argument(
        "--github-summary",
        action="store_true",
        help="also append the markdown report to $GITHUB_STEP_SUMMARY",
    )
    e.add_argument(
        "--annotate",
        action="store_true",
        help="print GitHub Actions annotations for the findings (on standard error)",
    )
    e.set_defaults(func=explain)
    r = sub.add_parser("rules", help="list the rules")
    r.add_argument("--markdown", action="store_true", help="as a markdown table")
    r.set_defaults(func=list_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
