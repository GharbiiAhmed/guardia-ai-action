# 🛡️ Guardia AI — EU AI Act Compliance Scanner

> Automatically scan your repository for AI libraries and check EU AI Act compliance on every pull request.

[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-Guardia%20AI-blue?logo=github)](https://github.com/marketplace/actions/guardia-ai-eu-ai-act-compliance-scanner)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Aug%202026-red)](https://guardia-ai.com)

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
        uses: guardia-ai/guardia-ai-action@v1
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
| `compliance-score` | Compliance score 0–100 (requires Guardia AI account) |

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

The EU AI Act general-purpose AI and high-risk AI provisions are **enforceable from August 2, 2026**.

Fines: up to **€35,000,000** or **7% of global annual turnover**.

Start your compliance audit free at [guardia-ai.com/free-audit](https://guardia-ai.com/free-audit).

---

## License

MIT © [Guardia AI](https://guardia-ai.com)
