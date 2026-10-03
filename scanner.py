"""CloudWatchdog scanner.

Looks for cost waste and security risks in one AWS account (one region for EC2).
It only READS your resources. It saves findings to DynamoDB and emails a summary via SNS.
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# ---- Settings: come from environment variables (set by Kubernetes ConfigMap/Secret) ----
REGION = os.environ.get("AWS_REGION", "ap-south-1")          # change to your region
TABLE_NAME = os.environ.get("TABLE_NAME", "CloudWatchdogFindings")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"  # true = print only

# ---- Rough prices in USD. Check the AWS pricing page for your region. These are estimates. ----
EBS_PRICE_PER_GB_MONTH = 0.08
SNAPSHOT_PRICE_PER_GB_MONTH = 0.05
UNUSED_EIP_PER_MONTH = 3.65  # about $0.005 per hour

SNAPSHOT_MAX_AGE_DAYS = 90
KEY_MAX_AGE_DAYS = 90
RISKY_PORTS = [22, 3389]  # SSH and RDP


def make_finding(check, resource_id, severity, monthly_cost, details):
    """Build one finding as a dict. DynamoDB needs Decimal, not float."""
    return {
        "finding_id": f"{check}#{resource_id}",  # partition key in DynamoDB
        "check": check,
        "resource_id": resource_id,
        "severity": severity,  # HIGH / MEDIUM / LOW
        "monthly_cost_usd": Decimal(str(round(monthly_cost, 2))),
        "details": details,
    }


# ------------------------------- COST CHECKS -------------------------------
def check_unattached_volumes(ec2):
    """EBS volumes with status 'available' are not attached to anything but still cost money."""
    findings = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
        for v in page["Volumes"]:
            cost = v["Size"] * EBS_PRICE_PER_GB_MONTH
            findings.append(make_finding(
                "unattached_volume", v["VolumeId"], "MEDIUM", cost,
                f"{v['Size']} GB volume is not attached to any instance"))
    return findings


def check_unused_elastic_ips(ec2):
    """An Elastic IP with no association is billed."""
    findings = []
    for addr in ec2.describe_addresses()["Addresses"]:
        if "AssociationId" not in addr:
            rid = addr.get("AllocationId", addr["PublicIp"])
            findings.append(make_finding(
                "unused_elastic_ip", rid, "MEDIUM", UNUSED_EIP_PER_MONTH,
                f"Elastic IP {addr['PublicIp']} is not associated with anything"))
    return findings


def check_stopped_instances(ec2):
    """Stopped instances do not pay for compute, but their disks are still billed."""
    findings = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]):
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                findings.append(make_finding(
                    "stopped_instance", inst["InstanceId"], "LOW", 0,
                    "Instance is stopped; its attached volumes are still billed"))
    return findings


def check_old_snapshots(ec2):
    """Snapshots you own that are older than SNAPSHOT_MAX_AGE_DAYS."""
    findings = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=SNAPSHOT_MAX_AGE_DAYS)
    paginator = ec2.get_paginator("describe_snapshots")
    for page in paginator.paginate(OwnerIds=["self"]):
        for s in page["Snapshots"]:
            if s["StartTime"] < cutoff:
                # VolumeSize is an upper bound; real snapshot cost is usually lower
                cost = s["VolumeSize"] * SNAPSHOT_PRICE_PER_GB_MONTH
                findings.append(make_finding(
                    "old_snapshot", s["SnapshotId"], "LOW", cost,
                    f"Snapshot older than {SNAPSHOT_MAX_AGE_DAYS} days (check it is not used by an AMI)"))
    return findings


# ------------------------------ SECURITY CHECKS ------------------------------
def port_is_covered(perm, port):
    """Does this security group rule cover the given port?"""
    if perm.get("IpProtocol") == "-1":  # -1 means all traffic
        return True
    return perm.get("FromPort", -1) <= port <= perm.get("ToPort", -1)


def check_open_security_groups(ec2):
    """Security groups that allow SSH/RDP from anywhere on the internet."""
    findings = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg["IpPermissions"]:
                open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                if not (open_v4 or open_v6):
                    continue
                for port in RISKY_PORTS:
                    if port_is_covered(perm, port):
                        findings.append(make_finding(
                            "open_security_group", f"{sg['GroupId']}:{port}", "HIGH", 0,
                            f"Security group '{sg['GroupName']}' allows port {port} from the whole internet"))
    return findings


def check_public_buckets():
    """Buckets without a full 'block public access' setting might be public."""
    s3 = boto3.client("s3")
    findings = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(cfg.values()):
                findings.append(make_finding(
                    "public_bucket", name, "HIGH", 0,
                    "Block Public Access is only partly enabled"))
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                findings.append(make_finding(
                    "public_bucket", name, "HIGH", 0,
                    "No Block Public Access configuration; bucket may be public"))
            else:
                raise
    return findings


def check_iam_users_without_mfa():
    iam = boto3.client("iam")
    findings = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                findings.append(make_finding(
                    "user_without_mfa", name, "HIGH", 0,
                    "IAM user has no MFA device"))
    return findings


def check_old_access_keys():
    """Active keys that were not used (or created) in the last KEY_MAX_AGE_DAYS."""
    iam = boto3.client("iam")
    findings = []
    now = datetime.now(timezone.utc)
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue
                last = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                last_used = last["AccessKeyLastUsed"].get("LastUsedDate", key["CreateDate"])
                age = (now - last_used).days
                if age > KEY_MAX_AGE_DAYS:
                    findings.append(make_finding(
                        "stale_access_key", key["AccessKeyId"], "MEDIUM", 0,
                        f"Key of user '{name}' not used for {age} days"))
    return findings


# --------------------------------- OUTPUT ---------------------------------
def save_findings(findings, scan_time):
    table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
    with table.batch_writer() as batch:
        for f in findings:
            batch.put_item(Item={**f, "scan_time": scan_time})


def build_summary(findings, scan_time):
    total = sum(f["monthly_cost_usd"] for f in findings)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    lines = [f"CloudWatchdog report - {scan_time}",
             f"Findings: {len(findings)}   Estimated waste: ${total}/month", ""]
    for f in sorted(findings, key=lambda x: order[x["severity"]]):
        lines.append(f"[{f['severity']}] {f['check']} - {f['resource_id']}: {f['details']}")
    return "\n".join(lines)


def send_summary(message, count):
    sns = boto3.client("sns", region_name=REGION)
    sns.publish(TopicArn=SNS_TOPIC_ARN,
                Subject=f"CloudWatchdog: {count} finding(s)",
                Message=message)


def main():
    ec2 = boto3.client("ec2", region_name=REGION)
    checks = [
        ("unattached volumes", lambda: check_unattached_volumes(ec2)),
        ("unused elastic IPs", lambda: check_unused_elastic_ips(ec2)),
        ("stopped instances", lambda: check_stopped_instances(ec2)),
        ("old snapshots", lambda: check_old_snapshots(ec2)),
        ("open security groups", lambda: check_open_security_groups(ec2)),
        ("public buckets", check_public_buckets),
        ("users without MFA", check_iam_users_without_mfa),
        ("old access keys", check_old_access_keys),
    ]

    all_findings, errors = [], 0
    for name, run in checks:
        try:
            result = run()
            print(f"[OK] {name}: {len(result)} finding(s)")
            all_findings.extend(result)
        except (ClientError, BotoCoreError) as e:
            # One failed check should not stop the others
            errors += 1
            print(f"[ERROR] {name}: {e}", file=sys.stderr)

    scan_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
    summary = build_summary(all_findings, scan_time)
    print("\n" + summary)

    if DRY_RUN:
        print("\nDRY_RUN is true: nothing saved, no email sent.")
    else:
        if all_findings:
            save_findings(all_findings, scan_time)
        if SNS_TOPIC_ARN:
            send_summary(summary, len(all_findings))

    # A non-zero exit code makes Kubernetes mark the Job as failed
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()