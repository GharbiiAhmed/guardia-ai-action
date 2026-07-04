#!/usr/bin/env python3
"""
Guardia AI GitHub Action — EU AI Act Compliance Scanner.
Scans the repository for AI libraries (Python, JS/TS, Go, Java, Ruby, Rust) and
AI usage hidden in config files, calls Guardia AI API (if configured), and posts
a compliance report as a PR comment.

Detection logic lives in detection.py (kept in sync with the Guardia backend).
"""
import base64
import os
import sys
from datetime import datetime
from typing import Optional

import httpx
from detection import LIBRARY_META, detect_file, scan_workspace, should_scan

# ---------- Configuration ----------
GUARDIA_API_URL = os.environ.get("GUARDIA_API_URL", "").rstrip("/")
GUARDIA_API_KEY = os.environ.get("GUARDIA_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "")
GITHUB_PR_NUMBER = os.environ.get("GITHUB_PR_NUMBER", "")
GITHUB_SHA = os.environ.get("GITHUB_SHA", "")
FAIL_ON_HIGH_RISK = os.environ.get("FAIL_ON_HIGH_RISK", "false").lower() == "true"
FAIL_ON_PROHIBITED = os.environ.get("FAIL_ON_PROHIBITED", "true").lower() == "true"
SCAN_BRANCH = os.environ.get("SCAN_BRANCH", "main")
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT", "")

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
        f"*Enforcement deadline: **August 2, 2026** ({(datetime(2026, 8, 2) - datetime.utcnow()).days} days away)*",
    ]

    return "\n".join(lines)


def post_pr_comment(comment: str) -> None:
    if not GITHUB_TOKEN or not GITHUB_REPO or not GITHUB_PR_NUMBER:
        print("[guardia] Skipping PR comment — no GITHUB_TOKEN, REPO, or PR_NUMBER set.")
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

    # Build and post PR comment
    comment = build_pr_comment(library_files, config_hits, risk_level, api_result)
    print("\n" + comment + "\n")
    post_pr_comment(comment)

    # Set GitHub Action outputs
    set_output("risk-level", risk_level)
    set_output("libraries-found", ",".join(library_files.keys()))
    set_output("config-indicators", ",".join(config_hits.keys()))
    compliance_score = str(api_result.get("confidence", 0)) if api_result else "0"
    set_output("compliance-score", compliance_score)

    # Determine exit code
    should_fail = (
        (risk_level == "prohibited" and FAIL_ON_PROHIBITED) or
        (risk_level == "high_risk" and FAIL_ON_HIGH_RISK)
    )

    if should_fail:
        print(f"\n[guardia] ❌ Failing CI: risk_level={risk_level} and fail-on-{risk_level} is enabled.")
        sys.exit(1)

    print(f"\n[guardia] ✅ Scan complete. Risk level: {risk_level}")
    sys.exit(0)


if __name__ == "__main__":
    main()
