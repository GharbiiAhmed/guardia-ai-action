"""A tamper-evident record of one scan.

The findings tell a developer what to fix. This tells an auditor what was true
on a given commit, on a given date, under a named version of the rule pack —
which is the question actually asked during a conformity assessment: *prove this
control was in place when you shipped*.

**What the hash does and does not prove.** Each bundle contains the SHA-256 of
its own canonical form, and the hash of the bundle before it. That makes the
sequence tamper-evident: altering a past record breaks every hash after it, so
a silent edit is not possible — you would have to rewrite the whole chain.

It does **not** prove the record is authentic. Anyone holding the file can
rebuild the chain from scratch. For authenticity an HMAC is computed when a
signing key is supplied, which binds the record to someone who holds that
secret. Overstating this would be exactly the kind of unearned claim the rest of
this package refuses to make, so the bundle states its own guarantee in a field
an auditor can read.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Optional

from .models import CodeScanResult
from .rules.base import Rule, registry

# Bumped when the shape of a bundle changes, so an old record stays readable.
FORMAT_VERSION = 1

# The rule pack's own version. An auditor asking "which rules ran in March?"
# needs this to be recorded, not inferred.
RULESET_VERSION = "2026.07.1"

GENESIS = "0" * 64


def _canonical(document: dict) -> bytes:
    """Byte-stable form of a bundle, so the same content always hashes alike."""
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _rule_manifest(rules: list[Rule]) -> list[dict]:
    """Which rules ran, and how much review each had at the time.

    Recording `reviewed_by` matters as much as the findings: a record that
    cannot say whether counsel had signed off invites the reader to assume it.
    """
    manifest = []
    for rule in rules:
        legal = rule.legal
        manifest.append({
            "rule_id": rule.rule_id,
            "article": legal.citation,
            "regulation_version": legal.regulation_version,
            "text_verified": legal.text_verified,
            "reviewed_by": legal.reviewed_by,
            "advisory": rule.advisory,
        })
    return sorted(manifest, key=lambda entry: entry["rule_id"])


def build(
    result: CodeScanResult,
    repo: str = "",
    commit_sha: str = "",
    previous_hash: Optional[str] = None,
    rules: list[Rule] | None = None,
    signing_key: Optional[str] = None,
) -> dict:
    """Assemble the record for one scan."""
    rules = rules if rules is not None else registry()

    body = {
        "format_version": FORMAT_VERSION,
        "ruleset_version": RULESET_VERSION,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "repo": repo,
        "commit_sha": commit_sha,
        "previous_hash": previous_hash or GENESIS,
        "rules": _rule_manifest(rules),
        "scan": {
            "files_scanned": result.files_scanned,
            "files_out_of_scope": result.files_out_of_scope,
            "duration_ms": result.duration_ms,
        },
        "summary": {
            "total": len(result.findings),
            "open": sum(
                1 for f in result.findings
                if not f.suppressed and not f.baselined
            ),
            "accepted": sum(1 for f in result.findings if f.suppressed),
            "baselined": sum(1 for f in result.findings if f.baselined),
            "advisory": sum(1 for f in result.findings if f.advisory),
        },
        "findings": sorted(
            (
                {
                    "fingerprint": f.fingerprint,
                    "rule_id": f.rule_id,
                    "file": f.file,
                    "line": f.line,
                    "symbol": f.symbol,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "state": (
                        "accepted" if f.suppressed
                        else "baselined" if f.baselined
                        else "open"
                    ),
                    "justification": f.suppression_reason,
                }
                for f in result.findings
            ),
            key=lambda entry: entry["fingerprint"],
        ),
        # Stated in the record itself, so nobody has to infer how much this
        # document is worth.
        "guarantee": (
            "Tamper-evident: each record hashes its own content and the record "
            "before it. Signed records also carry an HMAC binding them to the "
            "holder of the signing key. An unsigned chain proves internal "
            "consistency, not authenticity."
        ),
    }

    body["record_hash"] = hashlib.sha256(_canonical(body)).hexdigest()
    if signing_key:
        body["signature"] = hmac.new(
            signing_key.encode("utf-8"),
            body["record_hash"].encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    return body


def verify(bundle: dict, signing_key: Optional[str] = None) -> tuple[bool, str]:
    """Check one record against its own hash, and its signature if present."""
    document = {k: v for k, v in bundle.items() if k not in {"record_hash", "signature"}}
    expected = hashlib.sha256(_canonical(document)).hexdigest()
    if bundle.get("record_hash") != expected:
        return False, "record_hash does not match the record's contents"

    if signing_key:
        signature = bundle.get("signature")
        if not signature:
            return False, "record is unsigned but a signing key was supplied"
        want = hmac.new(
            signing_key.encode("utf-8"), expected.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, want):
            return False, "signature does not match the signing key"

    return True, "ok"


def verify_chain(bundles: list[dict], signing_key: Optional[str] = None) -> tuple[bool, str]:
    """Check a sequence of records, oldest first."""
    previous = GENESIS
    for index, bundle in enumerate(bundles):
        ok, reason = verify(bundle, signing_key)
        if not ok:
            return False, f"record {index}: {reason}"
        if bundle.get("previous_hash") != previous:
            return False, (
                f"record {index}: previous_hash does not match the record before it "
                f"— a record was altered or removed"
            )
        previous = bundle["record_hash"]
    return True, "ok"


def dumps(bundle: dict) -> str:
    return json.dumps(bundle, indent=2, sort_keys=True) + "\n"
