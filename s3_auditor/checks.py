"""
checks.py — the security rules. Pure Python: no AWS calls happen here.

Each check looks at one bucket's settings (plus the account's) and returns a
Finding, or None if the bucket passes. They're modeled on the S3 controls in
AWS's own Foundational Security Best Practices.

  PUBLIC_POLICY        bucket policy lets anyone ("*") access it        HIGH
  PUBLIC_ACL           ACL grants access to everyone / any AWS user     HIGH
  ACCOUNT_BPA_OFF      account-wide Block Public Access not fully on    MEDIUM
  BUCKET_BPA_OFF       bucket Block Public Access not fully on          MEDIUM
  NO_TLS_ENFORCEMENT   policy doesn't deny unencrypted (HTTP) requests  MEDIUM
  NO_DEFAULT_ENCRYPTION objects aren't encrypted at rest by default     MEDIUM
  VERSIONING_OFF       deleted/overwritten objects can't be recovered   LOW
  ACCESS_LOGGING_OFF   no record of who accessed what                   LOW
  ACLS_ENABLED         legacy ACLs still active (harder to reason about) LOW

If a setting couldn't be read (e.g. AccessDenied), its check is skipped
rather than guessed. The report lists those gaps separately.
"""

from dataclasses import dataclass

from .collector import BPA_FLAGS, AccountConfig, BucketConfig

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    resource: str  # a bucket name, or "account 123456789012"
    detail: str    # what's wrong, in one line
    fix: str       # what to do about it


# --- helpers -----------------------------------------------------------------

def _as_list(value) -> list:
    """Policy fields can be a single value or a list. Always get a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statements(policy: dict | None) -> list[dict]:
    return _as_list((policy or {}).get("Statement"))


def _bpa_on(config: dict | None, flag: str) -> bool:
    return bool(config and config.get(flag))


def _blocked(bucket: BucketConfig, account: AccountConfig, flag: str) -> bool:
    """A Block Public Access switch counts if it's on at EITHER level."""
    return _bpa_on(bucket.public_access_block, flag) or _bpa_on(account.public_access_block, flag)


def _is_everyone(principal) -> bool:
    """True for "Principal": "*" and "Principal": {"AWS": "*"}."""
    if principal == "*":
        return True
    return isinstance(principal, dict) and "*" in _as_list(principal.get("AWS"))


# --- account check -----------------------------------------------------------

def check_account_bpa(account: AccountConfig) -> Finding | None:
    if "public_access_block" in account.errors:
        return None
    missing = [f for f in BPA_FLAGS if not _bpa_on(account.public_access_block, f)]
    if not missing:
        return None
    return Finding(
        "ACCOUNT_BPA_OFF", "MEDIUM", f"account {account.account_id}",
        f"account-wide Block Public Access is missing: {', '.join(missing)}",
        "Turn on all four account-level Block Public Access settings. "
        "It's the single switch that stops any bucket from becoming public by mistake.",
    )


# --- bucket checks -----------------------------------------------------------

def check_public_policy(bucket: BucketConfig, account: AccountConfig) -> Finding | None:
    """
    A statement is public if it Allows, the Principal is everyone, and there's
    no Condition narrowing it down (like a specific VPC or source IP).
    """
    if "policy" in bucket.errors:
        return None
    public = [
        s for s in _statements(bucket.policy)
        if s.get("Effect") == "Allow" and _is_everyone(s.get("Principal")) and not s.get("Condition")
    ]
    if not public:
        return None
    actions = ", ".join(sorted({a for s in public for a in _as_list(s.get("Action"))}))

    if _blocked(bucket, account, "RestrictPublicBuckets"):
        return Finding(
            "PUBLIC_POLICY", "LOW", bucket.name,
            f"policy grants everyone {actions}, but Block Public Access is overriding it for now",
            "Remove the public statement so turning Block Public Access off later can't expose the bucket.",
        )
    return Finding(
        "PUBLIC_POLICY", "HIGH", bucket.name,
        f"bucket policy grants everyone on the internet {actions}",
        "Remove the \"Principal\": \"*\" statement and turn on Block Public Access. "
        "For a public website, serve it through CloudFront instead of a public bucket.",
    )


def check_public_acl(bucket: BucketConfig, account: AccountConfig) -> Finding | None:
    if "acl" in bucket.errors:
        return None
    # With ACLs disabled (BucketOwnerEnforced) or ignored by BPA, grants have no effect.
    if bucket.object_ownership == "BucketOwnerEnforced" or _blocked(bucket, account, "IgnorePublicAcls"):
        return None
    grants = []
    for grant in bucket.acl_grants:
        uri = grant.get("Grantee", {}).get("URI")
        if uri == ALL_USERS:
            grants.append(f"{grant['Permission']} to everyone (AllUsers)")
        elif uri == AUTHENTICATED_USERS:
            grants.append(f"{grant['Permission']} to any AWS account (AuthenticatedUsers)")
    if not grants:
        return None
    return Finding(
        "PUBLIC_ACL", "HIGH", bucket.name,
        f"ACL grants {'; '.join(grants)}",
        "Set Object Ownership to 'Bucket owner enforced' (disables ACLs) and turn on Block Public Access.",
    )


def check_bucket_bpa(bucket: BucketConfig, account: AccountConfig) -> Finding | None:
    if "public_access_block" in bucket.errors:
        return None
    if all(_bpa_on(account.public_access_block, f) for f in BPA_FLAGS):
        return None  # the account-level setting already covers every bucket
    missing = [f for f in BPA_FLAGS if not _bpa_on(bucket.public_access_block, f)]
    if not missing:
        return None
    return Finding(
        "BUCKET_BPA_OFF", "MEDIUM", bucket.name,
        f"Block Public Access is missing: {', '.join(missing)}",
        "Turn on all four Block Public Access settings for this bucket (or for the whole account).",
    )


def _denies_insecure_transport(policy: dict | None) -> bool:
    """Look for the standard 'Deny when aws:SecureTransport is false' statement."""
    for statement in _statements(policy):
        if statement.get("Effect") != "Deny":
            continue
        bool_conditions = statement.get("Condition", {}).get("Bool", {})
        # Condition keys are case-insensitive in AWS, so compare in lowercase.
        lowered = {key.lower(): value for key, value in bool_conditions.items()}
        values = [str(v).lower() for v in _as_list(lowered.get("aws:securetransport"))]
        if "false" in values:
            return True
    return False


def check_tls(bucket: BucketConfig, account: AccountConfig) -> Finding | None:
    if "policy" in bucket.errors or _denies_insecure_transport(bucket.policy):
        return None
    return Finding(
        "NO_TLS_ENFORCEMENT", "MEDIUM", bucket.name,
        "bucket policy doesn't reject plain-HTTP requests, so data can travel unencrypted",
        "Add a Deny statement with the condition \"Bool\": {\"aws:SecureTransport\": \"false\"}.",
    )


def check_encryption(bucket: BucketConfig, account: AccountConfig) -> Finding | None:
    if "encryption" in bucket.errors or bucket.encryption:
        return None
    return Finding(
        "NO_DEFAULT_ENCRYPTION", "MEDIUM", bucket.name,
        "no default encryption, so new objects may be stored unencrypted",
        "Enable default encryption (SSE-S3 at minimum; SSE-KMS for sensitive data).",
    )


def check_versioning(bucket: BucketConfig, account: AccountConfig) -> Finding | None:
    if "versioning" in bucket.errors or bucket.versioning == "Enabled":
        return None
    return Finding(
        "VERSIONING_OFF", "LOW", bucket.name,
        f"versioning is {bucket.versioning.lower()}, so deleted or overwritten objects are gone for good",
        "Enable versioning (pair it with a lifecycle rule to expire old versions and control cost).",
    )


def check_logging(bucket: BucketConfig, account: AccountConfig) -> Finding | None:
    if "logging" in bucket.errors or bucket.logging_enabled:
        return None
    return Finding(
        "ACCESS_LOGGING_OFF", "LOW", bucket.name,
        "server access logging is off, so there's no record of who accessed what",
        "Enable server access logging to a separate log bucket in the same region.",
    )


def check_acls_enabled(bucket: BucketConfig, account: AccountConfig) -> Finding | None:
    if "object_ownership" in bucket.errors or bucket.object_ownership == "BucketOwnerEnforced":
        return None
    return Finding(
        "ACLS_ENABLED", "LOW", bucket.name,
        f"legacy ACLs are still active (Object Ownership: {bucket.object_ownership or 'not set'})",
        "Set Object Ownership to 'Bucket owner enforced' so only IAM and bucket policies control access.",
    )


BUCKET_CHECKS = [
    check_public_policy,
    check_public_acl,
    check_bucket_bpa,
    check_tls,
    check_encryption,
    check_versioning,
    check_logging,
    check_acls_enabled,
]


def run_checks(account: AccountConfig, buckets: list[BucketConfig]) -> list[Finding]:
    """Run every check and return findings, most severe first."""
    findings = [check_account_bpa(account)]
    for bucket in buckets:
        findings += [check(bucket, account) for check in BUCKET_CHECKS]
    found = [f for f in findings if f is not None]
    return sorted(found, key=lambda f: (SEVERITY_ORDER[f.severity], f.resource, f.rule))
