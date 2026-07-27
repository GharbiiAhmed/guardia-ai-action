#!/usr/bin/env python3
"""
Guardia AI GitHub Action — EU AI Act Compliance Scanner.
Scans the repository for AI libraries (Python, JS/TS, Go, Java, Ruby, Rust) and
AI usage hidden in config files, calls Guardia AI API (if configured), and posts
a compliance report as a PR comment.

Detection logic lives in detection.py (kept in sync with the Guardia backend).
"""
import base64
import json
import os
import sys
from datetime import datetime
from typing import Optional

import httpx
from detection import LIBRARY_META, detect_file, scan_workspace, should_scan

# Vendored by sync_analyzer.sh — the action ships as a self-contained image and
# cannot import from the backend. Guarded so an image built before the sync
# still runs the library scan rather than crashing on import.
try:
    from code_analysis import analyze_workspace
    from code_analysis import baseline as baseline_module
    from code_analysis import evidence as evidence_module
    from code_analysis import sarif as sarif_output
    CODE_ANALYSIS_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on image build
    CODE_ANALYSIS_AVAILABLE = False

# ---------- Configuration ----------
GUARDIA_API_URL = os.environ.get("GUARDIA_API_URL", "").rstrip("/")
GUARDIA_API_KEY = os.environ.get("GUARDIA_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
# GitHub exports GITHUB_REPOSITORY and GITHUB_SHA to every action. An action's
# runs.env cannot reference the `github` context — only `inputs` — so reading
# the built-ins is the supported route. Setting them in action.yml made the
# action fail to load entirely.
GITHUB_REPO = os.environ.get("GITHUB_REPO") or os.environ.get("GITHUB_REPOSITORY", "")
def _pr_number() -> str:
    """The pull request number, from the event payload or the ref."""
    explicit = os.environ.get("GITHUB_PR_NUMBER", "")
    if explicit:
        return explicit
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            number = (payload.get("pull_request") or {}).get("number")
            if number:
                return str(number)
        except (OSError, ValueError):
            pass
    # refs/pull/123/merge
    ref = os.environ.get("GITHUB_REF", "")
    parts = ref.split("/")
    if len(parts) > 2 and parts[1] == "pull":
        return parts[2]
    return ""


GITHUB_PR_NUMBER = _pr_number()
GITHUB_SHA = os.environ.get("GITHUB_SHA", "")
FAIL_ON_HIGH_RISK = os.environ.get("FAIL_ON_HIGH_RISK", "false").lower() == "true"
FAIL_ON_PROHIBITED = os.environ.get("FAIL_ON_PROHIBITED", "true").lower() == "true"
SCAN_BRANCH = os.environ.get("SCAN_BRANCH", "main")
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT", "")

# Code analysis runs against the checked-out workspace, not the GitHub API —
# it needs real files on disk.
WORKSPACE = os.environ.get("GITHUB_WORKSPACE", ".")
ENABLE_CODE_ANALYSIS = os.environ.get("CODE_ANALYSIS", "true").lower() == "true"
SARIF_FILE = os.environ.get("SARIF_FILE", "guardia.sarif")
# Default 'none': a scanner should observe a repository before it blocks anyone.
FAIL_ON_FINDINGS = os.environ.get("FAIL_ON_FINDINGS", "none").lower()
# Findings that predate adoption. Without this a five-year-old repo lights
# up red on day one and the check gets deleted.
BASELINE_FILE = os.environ.get("BASELINE_FILE", ".guardia/baseline.json")
# A tamper-evident record of the run, for the audit trail rather than the
# developer. Empty disables it.
EVIDENCE_FILE = os.environ.get("EVIDENCE_FILE", "guardia-evidence.json")
EVIDENCE_PREVIOUS = os.environ.get("EVIDENCE_PREVIOUS", "")
EVIDENCE_SIGNING_KEY = os.environ.get("EVIDENCE_SIGNING_KEY", "")

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Findings are posted to the app, not the backend API: that is where the
# record lives and where the dashboard reads it from.
GUARDIA_APP_URL = os.environ.get("GUARDIA_APP_URL", "https://guardia-ai.com").rstrip("/")

RISK_LABELS = {
    "prohibited": "🚨 PROHIBITED",
    "high_risk": "🔴 HIGH RISK",
    "limited": "🟡 LIMITED RISK",
    "minimal": "🟢 MINIMAL RISK",
    "none": "✅ NO AI DETECTED",
}

KIND_LABELS = {
    "model_name": "Model name",
    "api_endpoint": "API endpoint",
    "env_key": "Credential env key",
}


def scan_github_repo(owner: str, repo: str, branch: str, token: Optional[str]) -> tuple[dict, dict]:
    """Scan repo via GitHub API. Returns (library_files, config_hits)."""
    headers = {"Accept": "application/vnd.github.v3+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    library_files: dict[str, list[str]] = {}
    config_hits: dict[str, tuple[str, str, list[str]]] = {}

    with httpx.Client(timeout=30) as client:
        tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        r = client.get(tree_url, headers=headers)
        if r.status_code != 200:
            print(f"[guardia] Warning: Could not fetch repo tree ({r.status_code}). Scanning current workspace instead.")
            return scan_local_workspace()
        tree = r.json()

        files = [
            item for item in tree.get("tree", [])
            if item["type"] == "blob" and should_scan(item["path"])
        ][:150]

        for file_item in files:
            path = file_item["path"]
            try:
                content_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"
                cr = client.get(content_url, headers=headers)
                if cr.status_code != 200:
                    continue
                raw = base64.b64decode(cr.json().get("content", "")).decode("utf-8", errors="ignore")
                libs, config_findings = detect_file(path, raw)
                for lib in libs:
                    library_files.setdefault(lib, [])
                    if path not in library_files[lib]:
                        library_files[lib].append(path)
                for kind, indicator, note in config_findings:
                    if indicator not in config_hits:
                        config_hits[indicator] = (kind, note, [])
                    if path not in config_hits[indicator][2]:
                        config_hits[indicator][2].append(path)
            except Exception:
                continue

    return library_files, config_hits


def scan_local_workspace() -> tuple[dict, dict]:
    """Fallback: scan the local filesystem (GitHub Actions workspace)."""
    workspace = os.environ.get("GITHUB_WORKSPACE", ".")
    return scan_workspace(workspace)


def determine_risk_level(library_files: dict, config_hits: dict) -> str:
    if not library_files and not config_hits:
        return "none"
    for lib in library_files:
        cat, note = LIBRARY_META.get(lib, ("", ""))
        if "biometric" in cat.lower() or "facial" in note.lower():
            return "high_risk"
    return "limited"


def call_guardia_api(library_files: dict) -> Optional[dict]:
    """Call Guardia AI backend for enhanced classification (optional)."""
    if not GUARDIA_API_URL or not GUARDIA_API_KEY:
        return None
    try:
        headers = {"Authorization": f"Bearer {GUARDIA_API_KEY}", "Content-Type": "application/json"}
        with httpx.Client(timeout=20) as client:
            r = client.post(
                f"{GUARDIA_API_URL}/v1/discover/classify",
                json={
                    "name": f"Repository: {GITHUB_REPO}",
                    "description": f"AI libraries detected: {', '.join(library_files.keys())}",
                    "sector": "general",
                    "affects_people": True,
                },
                headers=headers,
            )
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        print(f"[guardia] Could not reach Guardia AI API: {e}")
    return None


def build_pr_comment(library_files: dict, config_hits: dict, risk_level: str, api_result: Optional[dict]) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    risk_label = RISK_LABELS.get(risk_level, risk_level)

    lines = [
        "## 🛡️ Guardia AI — EU AI Act Compliance Scan",
        "",
        f"**Scan time:** {now}  |  **Commit:** `{GITHUB_SHA[:8]}`",
        "",
    ]

    if not library_files and not config_hits:
        lines += [
            "✅ **No AI libraries detected** in this pull request.",
            "",
            "> If you use AI tools that aren't detected here, consider registering them in your [Guardia AI dashboard](https://guardia-ai.com).",
        ]
        return "\n".join(lines)

    lines += [f"### Risk Assessment: {risk_label}", ""]

    if library_files:
        lines += [
            "| AI Library | Category | Files | EU AI Act Note |",
            "|-----------|----------|-------|----------------|",
        ]
        for lib, files in library_files.items():
            cat, note = LIBRARY_META.get(lib, ("Unknown", "Review required"))
            file_list = ", ".join(f"`{f}`" for f in files[:2])
            if len(files) > 2:
                file_list += f" +{len(files) - 2} more"
            lines.append(f"| `{lib}` | {cat} | {file_list} | {note} |")
        lines += [""]

    if config_hits:
        lines += [
            "### 🔍 AI usage found in configuration files",
            "",
            "| Indicator | Type | Files | Note |",
            "|-----------|------|-------|------|",
        ]
        for indicator, (kind, note, files) in config_hits.items():
            file_list = ", ".join(f"`{f}`" for f in files[:2])
            if len(files) > 2:
                file_list += f" +{len(files) - 2} more"
            lines.append(f"| `{indicator}` | {KIND_LABELS.get(kind, kind)} | {file_list} | {note} |")
        lines += [""]

    if api_result:
        confidence = api_result.get("confidence", "N/A")
        summary = api_result.get("summary", "")
        findings = api_result.get("findings", [])
        quick_wins = api_result.get("quick_wins", [])

        lines += [
            f"### Classification Details (Confidence: {confidence}%)",
            "",
            f"> {summary}",
            "",
        ]

        if findings:
            lines += ["**Compliance Gaps:**", ""]
            for f in findings[:5]:
                severity_icon = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢"}.get(f.get("severity", ""), "⚠️")
                lines.append(f"- {severity_icon} **{f.get('title')}** ({f.get('article')}) — {f.get('remediation')}")
            lines += [""]

        if quick_wins:
            lines += ["**Quick Wins:**", ""]
            for w in quick_wins[:3]:
                lines.append(f"- ✅ {w}")
            lines += [""]

    else:
        if risk_level in ("high_risk", "limited"):
            lines += [
                "### ⚠️ Action Required",
                "",
                "AI usage detected in this PR. Review the following before merging:",
                "",
                "- [ ] Register these AI systems in your [Guardia AI dashboard](https://guardia-ai.com)",
                "- [ ] Run a full risk classification",
                "- [ ] Ensure transparency notices are in place (Article 50)",
                "",
            ]

    lines += [
        "---",
        "",
        "*Powered by [Guardia AI](https://guardia-ai.com) — EU AI Act compliance for developers.*  ",
        f"*High-risk enforcement deadline: **2 December 2027** ({(datetime(2027, 12, 2) - datetime.utcnow()).days} days away)*",
    ]

    return "\n".join(lines)


def run_code_analysis():
    """Article-level findings from the source itself. Returns None if disabled."""
    if not ENABLE_CODE_ANALYSIS or not CODE_ANALYSIS_AVAILABLE:
        if ENABLE_CODE_ANALYSIS:
            print("[guardia] Code analysis unavailable in this image — skipping.")
        return None
    try:
        result = analyze_workspace(WORKSPACE)
    except Exception as e:
        # The library scan is still worth delivering if the analyzer trips.
        print(f"[guardia] Code analysis failed: {e}")
        return None

    known = baseline_module.load(os.path.join(WORKSPACE, BASELINE_FILE)) if BASELINE_FILE else None
    if known:
        baseline_module.apply(result, known)
        print(f"[guardia] Baseline: {len(known)} pre-existing finding(s) will not block.")

    print(
        f"[guardia] Code analysis: {len(result.findings)} finding(s) across "
        f"{result.files_scanned} file(s) in {result.duration_ms}ms"
    )
    if SARIF_FILE:
        try:
            with open(SARIF_FILE, "w", encoding="utf-8") as f:
                f.write(sarif_output.dumps(result))
            print(f"[guardia] SARIF written to {SARIF_FILE}")
        except OSError as e:
            print(f"[guardia] Could not write SARIF: {e}")

    write_evidence(result)
    return result


def write_evidence(result) -> None:
    """A record of what was true on this commit, for a conformity assessment.

    Never fails the run: an audit artifact is worth having, not worth breaking
    someone's pipeline over.
    """
    if not EVIDENCE_FILE:
        return
    previous_hash = None
    if EVIDENCE_PREVIOUS and os.path.exists(EVIDENCE_PREVIOUS):
        try:
            with open(EVIDENCE_PREVIOUS, "r", encoding="utf-8") as f:
                previous_hash = json.load(f).get("record_hash")
        except (OSError, ValueError):
            previous_hash = None
    try:
        bundle = evidence_module.build(
            result,
            repo=GITHUB_REPO,
            commit_sha=GITHUB_SHA,
            previous_hash=previous_hash,
            signing_key=EVIDENCE_SIGNING_KEY or None,
        )
        with open(EVIDENCE_FILE, "w", encoding="utf-8") as f:
            f.write(evidence_module.dumps(bundle))
        print(
            f"[guardia] Evidence record {bundle['record_hash'][:12]} written to "
            f"{EVIDENCE_FILE}"
        )
    except Exception as e:
        print(f"[guardia] Could not write evidence: {e}")


def upload_findings(result) -> None:
    """Send this scan to the customer's Guardia account.

    Optional by design: without a key the action still annotates the PR, it
    just does not accumulate a record. Failure here never fails the build —
    a compliance report is not worth breaking someone's pipeline over.
    """
    if result is None or not GUARDIA_API_KEY:
        return

    payload = {
        "repo": GITHUB_REPO,
        "commit_sha": GITHUB_SHA,
        "branch": SCAN_BRANCH,
        "findings": [
            {
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "file": f.file,
                "line": f.line,
                "symbol": f.symbol,
                "claim": f.claim,
                "article": (
                    f.legal.article + (f"({f.legal.paragraph})" if f.legal.paragraph else "")
                ),
                "article_text": f.legal.text,
                "severity": f.severity,
                "confidence": f.confidence,
                "suppressed": f.suppressed,
                "suppression_reason": f.suppression_reason,
                "fix_available": f.fix is not None,
                "fix_description": f.fix.description if f.fix else None,
                "fix_replacement": f.fix.replacement if f.fix else None,
                "fix_start_line": f.fix.start_line if f.fix else None,
                "fix_end_line": f.fix.end_line if f.fix else None,
            }
            for f in result.findings
        ],
    }

    try:
        with httpx.Client(timeout=20) as client:
            r = client.post(
                f"{GUARDIA_APP_URL}/api/code-findings",
                json=payload,
                headers={"Authorization": f"Bearer {GUARDIA_API_KEY}"},
            )
        if r.status_code == 200:
            body = r.json()
            print(
                f"[guardia] Recorded: {body.get('introduced', 0)} new, "
                f"{body.get('resolved', 0)} resolved since the last scan."
            )
        else:
            print(f"[guardia] Could not record findings: {r.status_code} {r.text[:200]}")
    except Exception as e:
        print(f"[guardia] Could not record findings: {e}")


def _diff_lines(owner_repo: str, pr_number: str) -> dict:
    """Line numbers touched by this pull request, per file.

    GitHub rejects a review comment on a line outside the diff, and rejects the
    whole review if any single comment is invalid — so the lines are checked
    before anything is posted rather than after.
    """
    touched: dict = {}
    try:
        with httpx.Client(timeout=20) as client:
            page = 1
            while page <= 10:
                r = client.get(
                    f"https://api.github.com/repos/{owner_repo}/pulls/{pr_number}/files",
                    params={"per_page": 100, "page": page},
                    headers={
                        "Authorization": f"Bearer {GITHUB_TOKEN}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )
                if r.status_code != 200:
                    break
                files = r.json()
                if not files:
                    break
                for entry in files:
                    patch = entry.get("patch") or ""
                    lines = set()
                    current = 0
                    for line in patch.splitlines():
                        if line.startswith("@@"):
                            # @@ -old,count +new,count @@
                            try:
                                current = int(line.split("+")[1].split(",")[0].split(" ")[0])
                            except (IndexError, ValueError):
                                current = 0
                        elif line.startswith("+"):
                            lines.add(current)
                            current += 1
                        elif not line.startswith("-"):
                            current += 1
                    touched[entry.get("filename")] = lines
                if len(files) < 100:
                    break
                page += 1
    except Exception as e:
        print(f"[guardia] Could not read the diff: {e}")
    return touched


def post_review_suggestions(result) -> None:
    """Offer each fix as a GitHub suggestion the author can apply in one click.

    This is the whole accept path: no approval UI of ours, just the button
    GitHub already draws on a review comment. Suggestions are only posted for
    lines this pull request actually touched — commenting on untouched code is
    both rejected by the API and rude.
    """
    if result is None or not (GITHUB_TOKEN and GITHUB_REPO and GITHUB_PR_NUMBER):
        return

    fixable = [
        f for f in result.findings
        if f.fix and not f.suppressed and not f.baselined
    ]
    if not fixable:
        return

    touched = _diff_lines(GITHUB_REPO, GITHUB_PR_NUMBER)
    comments = []
    for finding in fixable:
        lines = touched.get(finding.file)
        if not lines:
            continue
        span = range(finding.fix.start_line, finding.fix.end_line + 1)
        if not any(line in lines for line in span):
            continue

        body = (
            f"**{finding.rule_id}** — {finding.fix.description}\n\n"
            f"```suggestion\n{finding.fix.replacement}\n```\n\n"
            f"> {finding.legal.text}\n\n"
            f"Applying this is a judgement call: whether this payload is what "
            f"your users actually see is something only you can confirm."
        )
        comment = {
            "path": finding.file,
            "line": finding.fix.end_line,
            "side": "RIGHT",
            "body": body,
        }
        if finding.fix.end_line > finding.fix.start_line:
            comment["start_line"] = finding.fix.start_line
            comment["start_side"] = "RIGHT"
        comments.append(comment)

    if not comments:
        return

    try:
        with httpx.Client(timeout=20) as client:
            r = client.post(
                f"https://api.github.com/repos/{GITHUB_REPO}/pulls/{GITHUB_PR_NUMBER}/reviews",
                json={
                    "event": "COMMENT",
                    "body": (
                        "Guardia AI has suggested a fix for the findings below. "
                        "Apply, edit, or ignore — a finding closes itself once a "
                        "scan no longer sees it, however you resolved it."
                    ),
                    "comments": comments,
                },
                headers={
                    "Authorization": f"Bearer {GITHUB_TOKEN}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
        if r.status_code in (200, 201):
            print(f"[guardia] Posted {len(comments)} suggestion(s) on the pull request.")
        else:
            print(f"[guardia] Could not post suggestions: {r.status_code} {r.text[:200]}")
    except Exception as e:
        print(f"[guardia] Could not post suggestions: {e}")


def build_findings_section(result) -> list:
    """Findings as PR-comment markdown, quoting the obligation rather than
    asserting a verdict."""
    if result is None:
        return []

    active = [f for f in result.findings if not f.suppressed and not f.baselined]
    accepted = [f for f in result.findings if f.suppressed]
    baselined = [f for f in result.findings if f.baselined]

    lines = ["### 📄 Article-level findings", ""]
    if not active:
        lines += [
            f"No findings in {result.files_scanned} scanned file(s).",
            "",
        ]
    for f in active:
        citation = f.legal.article + (f"({f.legal.paragraph})" if f.legal.paragraph else "")
        lines += [
            f"**`{f.file}:{f.line}`** — {f.rule_id} · {f.severity}/{f.confidence} confidence",
            "",
            f"{f.claim}",
            "",
            f"> **{citation}**: {f.legal.text}",
            "",
        ]
        if f.fix:
            lines += [f"*Suggested fix available: {f.fix.description}*", ""]
        if not f.legal.reviewed_by:
            lines += ["*This rule has not yet been reviewed by legal counsel.*", ""]

    if accepted:
        lines += [f"{len(accepted)} finding(s) suppressed in source as accepted risks.", ""]
    if baselined:
        lines += [f"{len(baselined)} pre-existing finding(s) held in the baseline.", ""]

    lines += [
        "Findings state what the code does and quote the obligation. Whether an "
        "obligation applies depends on your system's purpose and deployment "
        "context, which a code scan cannot determine.",
        "",
    ]
    return lines


def post_pr_comment(comment: str) -> None:
    missing = [name for name, value in (
        ("GITHUB_TOKEN", GITHUB_TOKEN),
        ("GITHUB_REPOSITORY", GITHUB_REPO),
        ("PR number", GITHUB_PR_NUMBER),
    ) if not value]
    if missing:
        # Naming all three left no way to tell "this is a push, there is no PR"
        # apart from "the token was never passed and comments are broken".
        note = (" (expected on a push — there is no pull request to comment on)"
                if missing == ["PR number"] else "")
        print(f"[guardia] Skipping PR comment — {', '.join(missing)} not set{note}.")
        return
    try:
        with httpx.Client(timeout=15) as client:
            r = client.post(
                f"https://api.github.com/repos/{GITHUB_REPO}/issues/{GITHUB_PR_NUMBER}/comments",
                json={"body": comment},
                headers={
                    "Authorization": f"Bearer {GITHUB_TOKEN}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            if r.status_code == 201:
                print(f"[guardia] PR comment posted: {r.json().get('html_url')}")
            else:
                print(f"[guardia] Failed to post comment: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[guardia] Error posting PR comment: {e}")


def set_output(key: str, value: str) -> None:
    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write(f"{key}={value}\n")
    print(f"[guardia] output: {key}={value}")


def main() -> None:
    print("[guardia] Starting EU AI Act compliance scan...")
    print(f"[guardia] Repo: {GITHUB_REPO}  Branch: {SCAN_BRANCH}  SHA: {GITHUB_SHA[:8]}")

    # Parse owner/repo
    if "/" in GITHUB_REPO:
        owner, repo = GITHUB_REPO.split("/", 1)
    else:
        owner, repo = "", GITHUB_REPO

    # Scan
    if owner and repo:
        library_files, config_hits = scan_github_repo(owner, repo, SCAN_BRANCH, GITHUB_TOKEN or None)
    else:
        library_files, config_hits = scan_local_workspace()

    print(f"[guardia] Detected libraries: {list(library_files.keys()) or 'none'}")
    print(f"[guardia] Config indicators: {list(config_hits.keys()) or 'none'}")

    # Enhanced classification via Guardia AI API (optional)
    api_result = call_guardia_api(library_files) if library_files else None

    # Determine risk level
    if api_result:
        risk_level = api_result.get("risk_level", "minimal")
    else:
        risk_level = determine_risk_level(library_files, config_hits)

    # Article-level findings from the source itself
    analysis = run_code_analysis()
    upload_findings(analysis)
    post_review_suggestions(analysis)

    # Build and post PR comment
    comment = build_pr_comment(library_files, config_hits, risk_level, api_result)
    findings_section = build_findings_section(analysis)
    if findings_section:
        marker = "\n---\n\n*Powered by"
        addition = "\n".join(findings_section)
        if marker in comment:
            comment = comment.replace(marker, "\n" + addition + marker, 1)
        else:
            comment = comment + "\n" + addition
    print("\n" + comment + "\n")
    post_pr_comment(comment)

    # Set GitHub Action outputs
    set_output("risk-level", risk_level)
    set_output("libraries-found", ",".join(library_files.keys()))
    set_output("config-indicators", ",".join(config_hits.keys()))
    # This was published as "compliance score 0–100" while carrying the
    # classifier's confidence, and 0 whenever no classification came back — so a
    # repository with one advisory finding reported a score of zero. An absent
    # score is now absent rather than a failing grade, and the value is named
    # for what it is.
    classification_confidence = api_result.get("confidence") if api_result else None
    set_output("classification-confidence",
               "" if classification_confidence is None else str(classification_confidence))
    set_output("compliance-score",
               "" if classification_confidence is None else str(classification_confidence))
    if api_result is None and GUARDIA_API_KEY:
        print("[guardia] No classification returned — check guardia-api-url "
              f"(currently {GUARDIA_API_URL or 'unset'}). It is the backend API, "
              "not the app URL that records findings.")

    blocking = []
    if analysis is not None:
        active = [f for f in analysis.findings if not f.suppressed and not f.baselined]
        set_output("findings-count", str(len(active)))
        set_output("sarif-file", SARIF_FILE)
        if FAIL_ON_FINDINGS != "none":
            threshold = _SEVERITY_ORDER.get(FAIL_ON_FINDINGS, 99)
            # Suppressed findings never block: that is what an accepted risk is.
            # Advisory rules never gate: they read an obligation rather than
            # matching its plain words.
            blocking = [
                f for f in active
                if not f.advisory and _SEVERITY_ORDER.get(f.severity, 0) >= threshold
            ]
    else:
        set_output("findings-count", "0")

    # Determine exit code
    should_fail = (
        (risk_level == "prohibited" and FAIL_ON_PROHIBITED) or
        (risk_level == "high_risk" and FAIL_ON_HIGH_RISK)
    )

    if should_fail:
        print(f"\n[guardia] ❌ Failing CI: risk_level={risk_level} and fail-on-{risk_level} is enabled.")
        sys.exit(1)

    if blocking:
        print(
            f"\n[guardia] ❌ Failing CI: {len(blocking)} finding(s) at or above "
            f"'{FAIL_ON_FINDINGS}'."
        )
        sys.exit(1)

    print(f"\n[guardia] ✅ Scan complete. Risk level: {risk_level}")
    sys.exit(0)


if __name__ == "__main__":
    main()
