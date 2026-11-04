"""
report.py — turn the audit results into a text report or JSON.

The text report sticks to plain ASCII on purpose: the Windows console can
crash on characters like arrows or em-dashes.
"""

import json
from collections import Counter
from dataclasses import asdict

from .checks import Finding
from .collector import AccountConfig, BucketConfig

_ENCRYPTION_NAMES = {"AES256": "SSE-S3", "aws:kms": "SSE-KMS", "aws:kms:dsse": "DSSE-KMS"}


def _encryption_label(bucket: BucketConfig) -> str:
    if "encryption" in bucket.errors:
        return "?"
    return _ENCRYPTION_NAMES.get(bucket.encryption, bucket.encryption or "NONE")


def to_text(account: AccountConfig, buckets: list[BucketConfig], findings: list[Finding]) -> str:
    title = f"S3 security audit: account {account.account_id}"
    counts = Counter(f.severity for f in findings)
    out = [title, "=" * len(title)]
    out.append(f"Buckets checked   {len(buckets)}")
    out.append(
        f"Findings          {len(findings)}"
        f"  ({counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low)"
    )

    if buckets:
        exposed = {f.resource for f in findings if f.severity == "HIGH" and f.rule.startswith("PUBLIC_")}
        width = max(len(b.name) for b in buckets) + 2
        out += ["", "Buckets"]
        out.append(f"  {'NAME':<{width}}{'REGION':<16}{'PUBLIC':<8}{'ENCRYPTION':<12}{'VERSIONING':<12}LOGGING")
        for b in buckets:
            out.append(
                f"  {b.name:<{width}}{b.region:<16}{'YES' if b.name in exposed else 'no':<8}"
                f"{_encryption_label(b):<12}{b.versioning:<12}{'on' if b.logging_enabled else 'off'}"
            )

    out += ["", "Findings"]
    if not findings:
        out.append("  No issues found.")
    for f in findings:
        out.append(f"  [{f.severity}] {f.rule}  {f.resource}")
        out.append(f"      {f.detail}")
        out.append(f"      Fix: {f.fix}")

    gaps = [(f"account {account.account_id}", account.errors)] + [(b.name, b.errors) for b in buckets]
    gaps = [(name, errors) for name, errors in gaps if errors]
    if gaps:
        out += ["", "Couldn't check (these were skipped, not passed)"]
        for name, errors in gaps:
            out.append(f"  {name}: " + ", ".join(f"{check} ({code})" for check, code in errors.items()))

    return "\n".join(out) + "\n"


def to_json(account: AccountConfig, buckets: list[BucketConfig], findings: list[Finding]) -> str:
    report = {
        "account": asdict(account),
        "buckets": [asdict(b) for b in buckets],
        "findings": [asdict(f) for f in findings],
    }
    return json.dumps(report, indent=2) + "\n"
