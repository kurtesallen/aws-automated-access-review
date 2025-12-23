import csv
import io
import json
import logging
import os
from datetime import datetime, timezone
from typing import List, Tuple

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")
sns = boto3.client("sns")
s3 = boto3.client("s3")

REPORT_BUCKET = os.environ["REPORT_BUCKET"]
SNS_TOPIC = os.environ["SNS_TOPIC"]
SUPPRESSION_DAYS = int(os.environ.get("SUPPRESSION_DAYS", "7"))

ALERT_STATE_PREFIX = "alerts/"  # S3 prefix for per-user state


def calculate_risk(days_unused: int) -> Tuple[str, str]:
    """
    Map days of inactivity to a risk severity and optional emoji.

    Returns:
        (severity, emoji)
    """
    if days_unused >= 180:
        return "HIGH", "🔴"
    if days_unused >= 90:
        return "MEDIUM", "🟠"
    return "LOW", "🟢"


def _alert_state_key(username: str) -> str:
    return f"{ALERT_STATE_PREFIX}{username}.json"


def should_alert(username: str, severity: str) -> bool:
    """
    Alert only if:
    - The user has never been alerted, OR
    - The severity increased, OR
    - The suppression window has expired.
    """
    key = _alert_state_key(username)

    try:
        obj = s3.get_object(Bucket=REPORT_BUCKET, Key=key)
        data = json.loads(obj["Body"].read())

        last_alerted = datetime.fromisoformat(data["last_alerted"])
        previous_severity = data["severity"]

        # Severity increased (e.g., MEDIUM -> HIGH)
        if severity != previous_severity:
            logger.info(
                "Severity changed for %s: %s -> %s",
                username,
                previous_severity,
                severity,
            )
            return True

        # Suppression window expired
        delta_days = (datetime.now(timezone.utc) - last_alerted).days
        if delta_days >= SUPPRESSION_DAYS:
            logger.info(
                "Suppression window expired for %s (%d days).",
                username,
                delta_days,
            )
            return True

        # Otherwise, suppress
        logger.info(
            "Suppressing alert for %s (severity=%s, last_alerted=%s)",
            username,
            severity,
            last_alerted.isoformat(),
        )
        return False

    except s3.exceptions.NoSuchKey:
        # First time seeing this user
        logger.info("No previous alert state for %s. Alerting.", username)
        return True


def save_alert_state(username: str, severity: str) -> None:
    """Persist the last alert time and severity to S3."""
    key = _alert_state_key(username)
    body = json.dumps(
        {
            "last_alerted": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
        }
    )
    s3.put_object(Bucket=REPORT_BUCKET, Key=key, Body=body)
    logger.info("Saved alert state for %s", username)


def lambda_handler(event, context):
    logger.info("Starting IAM access review run.")
    now = datetime.now(timezone.utc)

    # Fetch IAM users
    response = iam.list_users()
    users = response.get("Users", [])
    logger.info("Found %d IAM users.", len(users))

    high: List[str] = []
    medium: List[str] = []
    report_rows: List[List[str]] = []

    for user in users:
        username = user["UserName"]
        last_used = user.get("PasswordLastUsed")

        if last_used is None:
            # Treat users with no password usage as very old
            days_unused = 999
        else:
            # Ensure tz-aware
            if last_used.tzinfo is None:
                last_used = last_used.replace(tzinfo=timezone.utc)
            days_unused = (now - last_used).days

        severity, emoji = calculate_risk(days_unused)

        # Skip low-risk users from alerting and CSV
        if severity == "LOW":
            continue

        if not should_alert(username, severity):
            continue

        report_rows.append([username, str(days_unused), severity])

        line = f"- {username} ({days_unused} days unused) {emoji}"
        if severity == "HIGH":
            high.append(line)
        else:
            medium.append(line)

        save_alert_state(username, severity)

    # Write CSV report if there are any relevant rows
    csv_key = f"access_review_{now.date().isoformat()}.csv"
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(["Username", "DaysUnused", "Severity"])
    writer.writerows(report_rows)

    s3.put_object(
        Bucket=REPORT_BUCKET,
        Key=csv_key,
        Body=csv_buffer.getvalue(),
    )
    logger.info("Wrote CSV report to s3://%s/%s", REPORT_BUCKET, csv_key)

    # Summary email (always send; contents show counts)
    subject = f"🟠 IAM Access Review Summary – {len(high)} High / {len(medium)} Medium Risks"

    message_lines = [
        "AWS IAM Access Review – Summary",
        "",
        f"Run Date: {now.date().isoformat()}",
        "",
        f"HIGH Risk Users ({len(high)}):",
        *(high or ["None"]),
        "",
        f"MEDIUM Risk Users ({len(medium)}):",
        *(medium or ["None"]),
        "",
        "Recommended Actions:",
        "- Review unused access",
        "- Remove unnecessary permissions",
        "- Enforce least-privilege policies",
        "",
        "A detailed CSV report is available in S3:",
        f"Bucket: {REPORT_BUCKET}",
        f"Key: {csv_key}",
    ]

    message = "\n".join(message_lines)

    sns.publish(TopicArn=SNS_TOPIC, Subject=subject, Message=message)
    logger.info(
        "Published summary email: %d HIGH, %d MEDIUM",
        len(high),
        len(medium),
    )

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "high_count": len(high),
                "medium_count": len(medium),
                "csv_key": csv_key,
            }
        ),
    }
