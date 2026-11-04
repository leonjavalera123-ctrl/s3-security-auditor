"""
cli.py — the command-line interface: reads arguments, runs the audit, and
turns AWS errors into clear messages instead of stack traces.

Credentials are never passed on the command line. boto3 finds them the
standard way (environment variables, ~/.aws/credentials, an SSO login, or an
IAM role), and --profile picks a named profile.

Exit codes (useful when a script or CI pipeline runs this):
  0  audit ran, no findings
  1  audit ran, findings reported
  2  something went wrong (no credentials, access denied, bad arguments)
"""

import argparse
import sys
from contextlib import nullcontext
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

from .checks import run_checks
from .collector import collect_account, collect_buckets, list_bucket_names
from .report import to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="s3_auditor",
        description="Read-only security audit of the S3 buckets in an AWS account.",
    )
    parser.add_argument("--demo", action="store_true", help="audit a simulated account (no AWS account needed)")
    parser.add_argument("--profile", help="AWS profile name from ~/.aws/config")
    parser.add_argument("--region", default="us-east-1", help="region for account-level API calls (default: us-east-1)")
    parser.add_argument("--bucket", action="append", metavar="NAME", help="only audit this bucket (repeatable)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="report format (default: text)")
    parser.add_argument("-o", "--output", type=Path, help="write the report to this file instead of the screen")
    return parser


def _error(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.demo:
        try:
            from .demo import demo_session
        except ImportError:
            return _error("--demo needs moto. Run: pip install -r requirements-dev.txt")
        context = demo_session()
    else:
        import boto3

        try:
            context = nullcontext(boto3.Session(profile_name=args.profile))
        except ProfileNotFound:
            return _error(f"AWS profile '{args.profile}' not found in ~/.aws/config")

    with context as session:
        try:
            account = collect_account(session, args.region)
            names = list_bucket_names(session, args.region)
            if args.bucket:
                unknown = sorted(set(args.bucket) - set(names))
                if unknown:
                    return _error(f"bucket not found in account {account.account_id}: {', '.join(unknown)}")
                names = [n for n in names if n in args.bucket]
            buckets = collect_buckets(session, names, args.region)
        except NoCredentialsError:
            return _error("no AWS credentials found. Run 'aws configure' or 'aws sso login', or pass --profile")
        except ClientError as exc:
            err = exc.response["Error"]
            return _error(f"AWS refused the request: {err['Code']}: {err.get('Message', '')}")
        except BotoCoreError as exc:
            return _error(f"couldn't reach AWS: {exc}")

    findings = run_checks(account, buckets)
    render = to_json if args.format == "json" else to_text
    report = render(account, buckets, findings)

    if args.output:
        try:
            args.output.write_text(report, encoding="utf-8")
        except OSError as exc:
            return _error(f"can't write {args.output}: {exc.strerror or exc}")
        print(f"Report written to {args.output} ({len(findings)} findings)")
    else:
        print(report, end="")

    return 1 if findings else 0
