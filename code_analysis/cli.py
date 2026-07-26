"""Command line entry point: ``python -m services.code_analysis <path>``.

This is what CI calls. It runs entirely offline — no network, no model, nothing
leaves the machine — because a scanner that phones home with customer source is
an objection that ends enterprise conversations before they start.

Exit codes:
    0  no findings above the fail threshold
    1  findings above the threshold (only when --fail-on is set)
    2  bad usage
"""
from __future__ import annotations

import argparse
import json
import sys

from . import baseline as baseline_module
from . import evidence as evidence_module
from . import rulecards as rulecards_module
from . import sarif
from .analyzer import analyze_workspace
from .rules.base import registry

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _render_text(result, root: str) -> str:
    lines: list[str] = []
    active = [f for f in result.findings if not f.suppressed and not f.baselined]
    suppressed = sum(1 for f in result.findings if f.suppressed)
    baselined = sum(1 for f in result.findings if f.baselined)

    if not active:
        lines.append("No findings.")
    for finding in active:
        legal = finding.legal
        citation = legal.citation
        marker = "  (advisory — never fails a check)" if finding.advisory else ""
        lines.append(
            f"{finding.file}:{finding.line}  {finding.rule_id}  "
            f"[{finding.severity}/{finding.confidence}]{marker}"
        )
        lines.append(f"    observed: {finding.claim}")
        lines.append(f"    {citation}: “{legal.text}”")
        if not legal.reviewed_by:
            lines.append("    (rule not yet reviewed by legal counsel)")
        lines.append("")

    lines.append(
        f"{len(active)} finding(s), {suppressed} suppressed, "
        + (f"{baselined} baselined, " if baselined else "")
        + f"{result.files_scanned} file(s) scanned"
        + (f", {result.files_out_of_scope} skipped as tests/examples/docs"
           if result.files_out_of_scope else "")
        + f" in {result.duration_ms}ms."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="guardia-scan",
        description="Find EU AI Act compliance evidence in source code. Runs offline.",
    )
    parser.add_argument("path", nargs="?", default=".", help="directory to scan")
    parser.add_argument("--format", choices=("text", "sarif", "json"), default="text")
    parser.add_argument("--output", "-o", help="write to a file instead of stdout")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="exit 1 when a finding at or above this severity is present "
             "(default: none — observe before blocking)",
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        help="also scan tests, examples and docs (off by default: they are "
             "not a system placed on the market)",
    )
    parser.add_argument(
        "--baseline",
        help="path to a baseline file; findings listed in it never fail the run",
    )
    parser.add_argument(
        "--write-baseline",
        metavar="PATH",
        help="freeze the findings of this scan into a baseline file and exit 0",
    )
    parser.add_argument(
        "--evidence",
        metavar="PATH",
        help="write a tamper-evident record of this scan for an audit trail",
    )
    parser.add_argument(
        "--evidence-previous",
        metavar="PATH",
        help="the previous evidence record, to chain this one to it",
    )
    parser.add_argument("--repo", default="", help="repository name, recorded in the evidence")
    parser.add_argument("--commit", default="", help="commit sha, recorded in the evidence")
    parser.add_argument(
        "--signing-key",
        help="HMAC key binding the record to its holder; without one the chain "
             "proves consistency but not authenticity",
    )
    parser.add_argument(
        "--rule-cards",
        metavar="PATH",
        help="write the rule pack as a review document for counsel and exit",
    )
    parser.add_argument(
        "--rule",
        action="append",
        help="run only this rule id; repeatable",
    )
    args = parser.parse_args(argv)

    rules = registry()
    if args.rule:
        wanted = {r.upper() for r in args.rule}
        rules = [r for r in rules if r.rule_id.upper() in wanted]
        if not rules:
            parser.error(f"no rules matched {sorted(wanted)}")

    if args.rule_cards:
        with open(args.rule_cards, "w", encoding="utf-8") as handle:
            handle.write(rulecards_module.to_markdown(rules))
        print(f"[guardia] Rule cards for {len(rules)} rule(s) written to "
              f"{args.rule_cards}.", file=sys.stderr)
        return 0

    result = analyze_workspace(args.path, rules=rules, include_non_shipped=args.include_tests)

    if args.write_baseline:
        with open(args.write_baseline, "w", encoding="utf-8") as handle:
            handle.write(baseline_module.dumps(result))
        print(
            f"[guardia] Baselined {len(result.findings)} finding(s) into "
            f"{args.write_baseline}.",
            file=sys.stderr,
        )
        return 0

    baseline_module.apply(result, baseline_module.load(args.baseline or ""))

    if args.format == "sarif":
        payload = sarif.dumps(result, rules)
    elif args.format == "json":
        payload = result.model_dump_json(indent=2)
    else:
        payload = _render_text(result, args.path)

    if args.evidence:
        previous_hash = None
        if args.evidence_previous:
            try:
                with open(args.evidence_previous, "r", encoding="utf-8") as handle:
                    previous_hash = json.load(handle).get("record_hash")
            except (OSError, json.JSONDecodeError):
                # A missing predecessor starts a new chain rather than failing:
                # the first run in any repository has nothing to chain to.
                previous_hash = None
        bundle = evidence_module.build(
            result,
            repo=args.repo,
            commit_sha=args.commit,
            previous_hash=previous_hash,
            rules=rules,
            signing_key=args.signing_key,
        )
        with open(args.evidence, "w", encoding="utf-8") as handle:
            handle.write(evidence_module.dumps(bundle))
        print(
            f"[guardia] Evidence record {bundle['record_hash'][:12]} written to "
            f"{args.evidence}.",
            file=sys.stderr,
        )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload)
        print(f"[guardia] wrote {args.format} to {args.output}", file=sys.stderr)
    else:
        print(payload)

    if args.fail_on != "none":
        threshold = _SEVERITY_ORDER[args.fail_on]
        # Accepted risks, pre-existing findings and advisory rules never block.
        blocking = [
            f for f in result.findings
            if not f.suppressed and not f.baselined and not f.advisory
            and _SEVERITY_ORDER.get(f.severity, 0) >= threshold
        ]
        if blocking:
            print(
                f"[guardia] {len(blocking)} finding(s) at or above '{args.fail_on}'.",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
