# S3 Security Auditor

A read-only command-line tool that checks every S3 bucket in an AWS account
for the misconfigurations behind real-world data leaks: public bucket
policies, public ACLs, missing Block Public Access, unencrypted transport, and
missing recovery or audit settings. Each finding comes with a severity and a
concrete fix.

Try it with **no AWS account** using the built-in demo, which runs against a
simulated account.

```powershell
python -m s3_auditor --demo
```

## What it checks

| Rule | Severity | What it means |
|------|----------|---------------|
| `PUBLIC_POLICY` | HIGH | The bucket policy grants `"Principal": "*"` with no conditions, so anyone on the internet has access |
| `PUBLIC_ACL` | HIGH | An ACL grants access to *AllUsers* (everyone) or *AuthenticatedUsers* (any AWS account at all) |
| `ACCOUNT_BPA_OFF` | MEDIUM | Account-wide Block Public Access isn't fully on |
| `BUCKET_BPA_OFF` | MEDIUM | The bucket's Block Public Access isn't fully on, and the account setting doesn't cover it |
| `NO_TLS_ENFORCEMENT` | MEDIUM | The policy doesn't reject plain-HTTP requests |
| `NO_DEFAULT_ENCRYPTION` | MEDIUM | Objects aren't encrypted at rest by default |
| `VERSIONING_OFF` | LOW | Deleted or overwritten objects can't be recovered (ransomware, mistakes) |
| `ACCESS_LOGGING_OFF` | LOW | No record of who accessed what |
| `ACLS_ENABLED` | LOW | Legacy ACLs are still active alongside IAM, which makes access harder to reason about |

The checks understand how S3 settings interact, as AWS does:
- A public policy that Block Public Access is overriding is reported as LOW,
  not HIGH. It's safe today but one setting change from exposed.
- Public ACLs don't count when ACLs are disabled (Object Ownership set to
  *Bucket owner enforced*).
- Bucket-level Block Public Access isn't required when the account-level
  setting already covers every bucket.

Some findings can be intentional (a static website bucket, for example). The
report is a list to review, not a list of mistakes.

## What you'll learn
- **boto3**, the AWS SDK for Python: sessions, clients, per-region calls, and
  the credential chain.
- **AWS error handling.** "Not configured" (`NoSuchBucketPolicy`) is a normal
  answer, not a failure. `AccessDenied` means a check was *skipped*, and the
  report says so instead of guessing.
- **Reading IAM policy JSON**: principals, conditions, and the
  `aws:SecureTransport` pattern.
- **Separating I/O from logic.** `collector.py` is the only file that talks to
  AWS. The rules in `checks.py` work on plain data, so they're tested without
  AWS at all.
- **Mocking cloud services** with `moto`, so tests and the demo never touch a
  real account.

## File tour
| File | Role |
|------|------|
| `s3_auditor/collector.py` | Read-only AWS calls → `AccountConfig` / `BucketConfig` objects. |
| `s3_auditor/checks.py`    | The nine security rules, which produce `Finding`s. |
| `s3_auditor/report.py`    | Text and JSON reports. |
| `s3_auditor/cli.py`       | Arguments, AWS error messages, exit codes. |
| `s3_auditor/demo.py`      | A simulated account ("Acme", five buckets) built with moto. |
| `tests/`                  | 40 pytest tests: rules, collector (against moto), and end-to-end. |

## Setup

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt   # boto3 + moto + pytest
```

`requirements.txt` holds just `boto3`, which is all a real audit needs.

## Run the demo

```powershell
python -m s3_auditor --demo                       # text report
python -m s3_auditor --demo --format json         # machine-readable
python -m s3_auditor --demo --bucket acme-data-lake
```

The demo account has five buckets: one fully hardened (zero findings), one
made public by a bucket policy, one made public by a legacy ACL, one with a
public policy that Block Public Access is overriding, and the log bucket.

## Run it against a real AWS account

The auditor only reads. Every call is a `Get*` or `List*`, so it can't change
anything. A full run is a handful of API requests, which costs a fraction of
a cent.

**1. Give it a least-privilege identity.** Attach this policy to the IAM role
or user that will run the audit:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3AuditReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketOwnershipControls"
      ],
      "Resource": "*"
    }
  ]
}
```

(`sts:GetCallerIdentity`, used to read the account ID, needs no permission.)

**2. Sign in the AWS way. Never put keys in this folder.** The preferred
option is IAM Identity Center, which uses short-lived credentials with no
keys on disk:

```powershell
aws configure sso       # one-time setup
aws sso login --profile audit
python -m s3_auditor --profile audit
```

Credentials live in your user profile (`~/.aws/`), never in the project.
`.gitignore` also blocks `.env`, `credentials*`, and key files as a backstop.

**3. Read the exit code** (handy in scripts and CI):

| Code | Meaning |
|------|---------|
| 0 | Audit ran, no findings |
| 1 | Audit ran, findings reported |
| 2 | Error: no credentials, access denied, unknown bucket or profile |

If the identity can't read some setting, that check is listed under
"Couldn't check" in the report. It is not silently treated as a pass.

## Running the tests

```powershell
pytest
```

The tests use moto and hide any real AWS credentials on the machine, so they
never contact AWS.

## Known limitations (good next steps)
- **Simplified "is it public?" logic.** Any `Condition` makes a statement
  count as non-public. AWS's real analysis is finer-grained (for example, a
  condition on `aws:PrincipalOrgID` is restrictive, but some conditions
  aren't). The `GetBucketPolicyStatus` API could be used as a second opinion.
- **No object-level checks.** Individual objects can have their own ACLs.
- **General-purpose buckets only.** Directory buckets (S3 Express One Zone)
  and access points aren't covered.
- **Since April 2023, AWS turns on Block Public Access and disables ACLs for
  new buckets by default.** Most HIGH findings in real accounts come from
  older buckets or deliberate changes, which is exactly what this tool helps
  catch.
