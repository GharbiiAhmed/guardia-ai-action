# 🛡️ Guardia AI — EU AI Act Compliance Scanner

> Automatically scan your repository for AI libraries and check EU AI Act compliance on every pull request.

[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-Guardia%20AI-blue?logo=github)](https://github.com/marketplace/actions/guardia-ai-eu-ai-act-compliance-scanner)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Dec%202027-blue)](https://guardia-ai.com)

---

## What it does

Every time a PR is opened, Guardia AI:

1. Scans your codebase for 28+ AI libraries (OpenAI, LangChain, TensorFlow, HuggingFace, facial recognition, and more)
2. Classifies the risk level under the EU AI Act (Prohibited / High Risk / Limited / Minimal)
3. Posts a compliance report directly as a PR comment
4. Optionally **fails the CI check** if prohibited or high-risk AI is detected without compliance coverage

No account required for basic scanning. Connect your Guardia AI account for full Article 9–14 compliance analysis.

---

## Quick start

Add this to `.github/workflows/guardia.yml` in your repo:

```yaml
name: EU AI Act Compliance Check

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main, master]

jobs:
  guardia-ai-scan:
    name: Guardia AI — EU AI Act Scan
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      contents: read

    steps:
      - name: EU AI Act Compliance Scan
        uses: GharbiiAhmed/guardia-ai-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on-prohibited: 'true'
```

---

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `github-token` | GitHub token for posting PR comments | Yes | `${{ github.token }}` |
| `guardia-api-url` | Your Guardia AI backend URL | No | `https://api.guardia-ai.com` |
| `guardia-api-key` | Guardia AI API key (from dashboard → API Keys) | No | — |
| `fail-on-high-risk` | Fail CI if HIGH RISK AI detected without compliance | No | `false` |
| `fail-on-prohibited` | Fail CI if PROHIBITED AI practice detected | No | `true` |
| `scan-branch` | Branch to scan | No | Current branch |

## Outputs

| Output | Description |
|--------|-------------|
| `risk-level` | Highest risk found: `prohibited` \| `high_risk` \| `limited` \| `minimal` \| `none` |
| `libraries-found` | Comma-separated list of AI libraries detected |
| `classification-confidence` | How confident the risk classification is. Empty when no Guardia account is configured. |
| `compliance-score` | Deprecated alias for `classification-confidence`. This action does not compute a compliance score — whether you comply depends on your system's purpose and deployment context, which a code scan cannot determine. |

---

## Example PR comment

When the action runs on a PR, it posts a comment like this:

```
🛡️ Guardia AI — EU AI Act Compliance Scan

Scan time: 2026-06-16 10:32 UTC  |  Commit: a1b2c3d4

### Risk Assessment: 🔴 HIGH RISK

| AI Library     | Category     | Files          | EU AI Act Note                         |
|----------------|--------------|----------------|----------------------------------------|
| `transformers` | ML Framework | `src/model.py` | HuggingFace Transformers detected      |
| `deepface`     | Biometric AI | `app/verify.py`| FACIAL RECOGNITION detected — HIGH RISK|

⚠️ Action Required
- [ ] Register these AI systems in your Guardia AI dashboard
- [ ] Run a full risk classification
- [ ] Ensure transparency notices are in place (Article 50)
```

---

## AI libraries detected

The scanner detects 28+ libraries across categories:

| Category | Libraries |
|----------|-----------|
| LLM APIs | `openai`, `anthropic`, `google-generativeai`, `cohere`, `mistralai`, `groq`, `replicate` |
| ML Frameworks | `torch`, `tensorflow`, `keras`, `sklearn`, `xgboost`, `lightgbm` |
| AI Orchestration | `langchain`, `llama-index` |
| Biometric AI | `deepface`, `face-recognition`, `mediapipe` |
| Cloud AI | `boto3` (SageMaker/Rekognition), `google-cloud-aiplatform`, `azure-cognitiveservices` |
| Model Hub | `huggingface_hub`, `transformers`, `diffusers` |
| Vector DBs | `pinecone`, `chromadb`, `weaviate` |

---

## Enhanced classification (optional)

Connect your [Guardia AI](https://guardia-ai.com) account for:

- Full EU AI Act Article 5, 9, 10, 11, 12, 13, 14 analysis
- Specific compliance gaps with article references
- Remediation steps and quick wins
- Annex IV technical documentation pre-fill

Add to your repo secrets:
- `GUARDIA_API_URL` — your backend URL
- `GUARDIA_API_KEY` — from Guardia AI dashboard → API Keys

---

## EU AI Act enforcement

The EU AI Act's general-purpose AI and transparency provisions apply from **August 2, 2026**; the high-risk (Annex III) provisions apply from **2 December 2027** (deferred by the 2026 Digital Omnibus).

Fines: up to **€35,000,000** or **7% of global annual turnover**.

Start your compliance audit free at [guardia-ai.com/free-audit](https://guardia-ai.com/free-audit).

---

## License

MIT © [Guardia AI](https://guardia-ai.com)

---

## Article-level code findings

Beyond detecting *which* AI libraries you use, the scanner reads your source and
reports specific obligations at specific lines:

| Rule | What it looks for |
|------|-------------------|
| `GA-ART50-001` | A user-facing endpoint that reaches a model, with no disclosure anywhere in the repository that responses are AI-generated |
| `GA-ART12-001` | A model invoked with no logging, audit or tracing call in scope |

Findings appear three ways: as a comment on the pull request, as inline
annotations via SARIF (upload it to code scanning), and — with an API key — as a
record in your Guardia dashboard that tracks what you fixed and what you
introduced, commit by commit.

```yaml
- uses: GharbiiAhmed/guardia-ai-action@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    guardia-api-key: ${{ secrets.GUARDIA_API_KEY }}   # optional — keeps the record
    code-analysis: 'true'
    fail-on-findings: 'none'    # observe first; switch to 'high' when you're ready

- uses: github/codeql-action/upload-sarif@v3
  continue-on-error: true
  with:
    sarif_file: guardia.sarif
```

The job needs `security-events: write` for the upload and `actions: read`, which
`upload-sarif` uses to attach results to the run.

**Code scanning is not available on every repository.** A private repository
needs GitHub Advanced Security for it; without that the upload fails, which is
why the step above is `continue-on-error`. Nothing else is affected — the PR
comment, the inline suggestions and the dashboard record all still work, and the
SARIF file is on disk if you want to keep it as a build artifact.

### Accepting a finding

Findings resolve themselves. Fix the code — our patch or your own — and the next
scan simply stops reporting it. Nothing to click.

To accept one instead, say so in the code:

```python
# guardia: ignore GA-ART50-001 — notice is rendered by the chat UI shell
```

That never fails a build, and it arrives in your dashboard as a documented risk
acceptance with the author from git blame, which is what an auditor wants to see.

### Adopting on an existing codebase

A five-year-old repository will have findings nobody currently on the team
caused. Freeze them once, and only new work has to be clean:

```
guardia-scan . --write-baseline .guardia/baseline.json
```

Commit that file. Baselined findings stay visible in the report and in your
dashboard — they just never fail the check. Anything introduced afterwards does.

### Evidence for an audit

Each run can write a tamper-evident record — what was found, on which commit,
under which version of the rule pack, and how much legal review each rule had at
the time:

```yaml
- uses: GharbiiAhmed/guardia-ai-action@v1
  with:
    evidence-file: guardia-evidence.json
    evidence-signing-key: ${{ secrets.GUARDIA_EVIDENCE_KEY }}   # optional
```

Records chain by hash, so altering a past one breaks every record after it.
Without a signing key that proves internal consistency, not authenticity — the
record says so itself rather than leaving you to assume.

### What it does not do

Findings state what your code does and quote the obligation. They do not assert
that you are in breach — whether an obligation applies depends on your system's
purpose and deployment context, which no code scan can determine. The rules cite
Regulation (EU) 2024/1689 verbatim so you can check the reasoning yourself.

Detection runs entirely offline. Your source never leaves the runner.
