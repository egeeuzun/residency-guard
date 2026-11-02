"""Uctan uca: naif LZ surumu + ayakta Frankfurt baseline'i ("once" durumu).

Akis dokumanindaki 2.4 tablosunun beklenen bulgularini uretmeli: uygulama ve
Exec loglari, Frankfurt'taki NAT, dis cagrilar ve baseline'in kaynaklari.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from residency_guard.aws import Context
from residency_guard.checks import run_checks
from residency_guard.config import Config
from residency_guard.model import Status
from residency_guard.report import Meta, exit_code, render_json, render_markdown
from tests.fakes import FakeClientError, FakeSession

ACCOUNT = "123456789012"
R = "eu-central-1"
LZ = "eu-central-1-ist-1a"
VPC = "vpc-0aaa1111bbbb2222c"

PERSONAL = {"data-residency": "tr", "data-class": "personal"}


def tagset(d: dict[str, str]) -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in d.items()]


def arn(service: str, resource: str, region: str = R) -> str:
    return f"arn:aws:{service}:{region}:{ACCOUNT}:{resource}"


TAGGED = [
    (arn("ec2", "instance/i-0db"), PERSONAL),
    (arn("ec2", "volume/vol-0data"), {**PERSONAL, "lz-woo-snapshot": "lz-woo-ist-db"}),
    (f"arn:aws:ec2:{R}::snapshot/snap-0aaaaaaaaaaaaaaa1", PERSONAL),
    (arn("rds", "db:lz-woo-test-db"), PERSONAL),
    (arn("rds", "snapshot:rds:lz-woo-test-db-2026-10-30"), PERSONAL),
    (arn("logs", "log-group:/ecs/lz-woo-ist-wordpress"), PERSONAL),
    (arn("ec2", "security-group/sg-0abc"), PERSONAL),
    ("arn:aws:s3:::lz-woo-ist-static-123", {"data-residency": "tr", "data-class": "non-personal"}),
    (arn("kinesis", "stream/orders"), {"data-residency": "tr"}),
]

SNAPSHOTS = [
    {"SnapshotId": "snap-0aaaaaaaaaaaaaaa1", "VolumeId": "vol-0data", "AvailabilityZone": LZ,
     "DataEncryptionKeyId": "dek-1", "Tags": tagset(PERSONAL)},
    # Elle alinmis, etiketi kopyalanmamis: Frankfurt'ta (AvailabilityZone yok)
    {"SnapshotId": "snap-0bbbbbbbbbbbbbbb2", "VolumeId": "vol-0data", "Description": "elle", "Tags": []},
    # Onun kopyasi: VolumeId anlamsiz, aciklama kaynagi gosterir
    {"SnapshotId": "snap-0ccccccccccccccc3", "VolumeId": "vol-ffffffff",
     "Description": "[Copied snap-0bbbbbbbbbbbbbbb2 from eu-central-1]"},
    {"SnapshotId": "snap-0ddddddddddddddd4", "VolumeId": "vol-0other"},
]

FLOW_ROWS = [
    {"subnet_id": "subnet-0app", "dstaddr": "52.28.10.1", "service": "AMAZON", "bytes": "5000000", "packets": "4000"},
    {"subnet_id": "subnet-0app", "dstaddr": "198.143.164.252", "service": "-", "bytes": "200000", "packets": "300"},
    {"subnet_id": "subnet-0app", "dstaddr": "10.1.20.10", "service": "-", "bytes": "9000000", "packets": "9000"},
    {"subnet_id": "subnet-0data", "dstaddr": "91.189.91.81", "service": "-", "bytes": "80000000", "packets": "60000"},
    {"subnet_id": "subnet-0pub", "dstaddr": "18.66.2.3", "service": "CLOUDFRONT", "bytes": "30000000", "packets": "25000"},
]

DNS_ROWS = [
    {"name": "ecs.eu-central-1.amazonaws.com", "queries": "900"},
    {"name": "api.wordpress.org", "queries": "40"},
    {"name": "secure.gravatar.com", "queries": "3"},
    {"name": "eu-central-1.ec2.archive.ubuntu.com", "queries": "12"},
    {"name": "d111111abcdef8.cloudfront.net", "queries": "60"},
]


def athena_ops() -> dict:
    state: dict[str, str] = {}

    def start(**kw):
        state["sql"] = kw["QueryString"]
        assert kw["WorkGroup"] == "lz-woo-ist-residency-guard"
        return {"QueryExecutionId": "q-1"}

    def results(**kw):
        rows = FLOW_ROWS if "flow_logs" in state["sql"] else DNS_ROWS
        header = list(rows[0])
        data = [{"Data": [{"VarCharValue": h} for h in header]}]
        data += [{"Data": [{"VarCharValue": r[h]} for h in header]} for r in rows]
        return {"ResultSet": {"Rows": data}}

    return {
        "start_query_execution": start,
        "get_query_execution": {"QueryExecution": {"Status": {"State": "SUCCEEDED"}}},
        "get_query_results": results,
    }


def describe_snapshots(**kw):
    if "SnapshotIds" in kw:
        return {"Snapshots": [s for s in SNAPSHOTS if s["SnapshotId"] in kw["SnapshotIds"]]}
    return {"Snapshots": SNAPSHOTS}


def describe_db_instances(**kw):
    if kw["DBInstanceIdentifier"] == "lz-woo-test-db":
        return {"DBInstances": [{"AvailabilityZone": "eu-central-1a"}]}
    raise FakeClientError("DBInstanceNotFound")


def filter_log_events(**kw):
    messages = {
        "/ecs/lz-woo-ist-wordpress": [
            '10.1.1.5 - - [01/Nov/2026] "GET / HTTP/1.1" 200 5123 "-" "k6" 85.105.12.34',
            '10.1.1.5 - - [01/Nov/2026] "GET /health.php HTTP/1.1" 200 2',
        ],
        "/ecs/lz-woo-ist-exec": ["ayse.yilmaz@example.com 12345678950"],
        "/aws/ecs/containerinsights/lz-woo-ist-cluster/performance": ['{"Type":"Task","CpuUtilized":3.2}'],
    }[kw["logGroupName"]]
    return {"events": [{"message": m} for m in messages]}


def log_group(name: str) -> dict:
    return {"logGroupName": name, "logGroupArn": arn("logs", f"log-group:{name}"), "storedBytes": 0,  # gercekte yeni gruplarda 0 kalir
            "retentionInDays": 30}


def ecs_ops() -> dict:
    clusters = {
        "lz": arn("ecs", "cluster/lz-woo-ist-cluster"),
        "fra": arn("ecs", "cluster/lz-woo-test-cluster"),
    }
    tasks = {
        clusters["lz"]: [{"group": "service:lz-woo-ist-service", "availabilityZone": LZ,
                          "capacityProviderName": "lz-woo-ist-ec2"}] * 2,
        clusters["fra"]: [{"group": "service:lz-woo-test-service", "availabilityZone": "eu-central-1a",
                           "launchType": "FARGATE"},
                          {"group": "service:lz-woo-test-service", "availabilityZone": "eu-central-1b",
                           "launchType": "FARGATE"}],
    }
    return {
        "list_clusters": {"clusterArns": list(clusters.values())},
        "describe_clusters": {"clusters": [
            {"clusterName": "lz-woo-ist-cluster", "configuration": {"executeCommandConfiguration": {
                "logging": "OVERRIDE", "logConfiguration": {"cloudWatchLogGroupName": "/ecs/lz-woo-ist-exec"}}}},
            {"clusterName": "lz-woo-test-cluster"},
        ]},
        "list_tasks": lambda **kw: {"taskArns": [f"{kw['cluster']}/t{i}" for i in range(len(tasks[kw["cluster"]]))]},
        "describe_tasks": lambda **kw: {"tasks": tasks[kw["cluster"]]},
    }


def build_session() -> FakeSession:
    subnets = [
        ("subnet-0pub", LZ, "10.1.1.0/24", "lz-woo-ist-lz-public"),
        ("subnet-0app", LZ, "10.1.10.0/24", "lz-woo-ist-lz-app-private"),
        ("subnet-0data", LZ, "10.1.20.0/24", "lz-woo-ist-lz-data-private"),
        ("subnet-0nat", "eu-central-1a", "10.1.100.0/24", "lz-woo-ist-parent-public"),
    ]
    empty_region = {
        "resourcegroupstaggingapi": {"get_resources": {"ResourceTagMappingList": []}},
        "ec2": {"describe_snapshots": {"Snapshots": []}},
        "rds": {"describe_db_snapshots": {"DBSnapshots": []}},
        "backup": {"list_backup_vaults": {"BackupVaultList": []}},
    }
    clients = {
        ("resourcegroupstaggingapi", R): {"get_resources": {"ResourceTagMappingList": [
            {"ResourceARN": a, "Tags": tagset(t)} for a, t in TAGGED
        ]}},
        ("ec2", R): {
            "describe_instances": {"Reservations": [{"Instances": [
                {"State": {"Name": "running"}, "Placement": {"AvailabilityZone": LZ}}]}]},
            "describe_volumes": {"Volumes": [{"AvailabilityZone": LZ}]},
            "describe_snapshots": describe_snapshots,
            "describe_vpcs": {"Vpcs": [{"CidrBlock": "10.1.0.0/16"}]},
            "describe_subnets": {"Subnets": [
                {"SubnetId": i, "AvailabilityZone": az, "CidrBlock": c, "Tags": [{"Key": "Name", "Value": n}]}
                for i, az, c, n in subnets
            ]},
            "describe_route_tables": {"RouteTables": [
                {"Associations": [{"Main": True}], "Routes": [{"DestinationCidrBlock": "10.1.0.0/16"}]},
                {"Associations": [{"SubnetId": "subnet-0pub"}, {"SubnetId": "subnet-0nat"}],
                 "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-0abc"}]},
                {"Associations": [{"SubnetId": "subnet-0app"}, {"SubnetId": "subnet-0data"}],
                 "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-0fra"}]},
            ]},
            "describe_nat_gateways": {"NatGateways": [{"NatGatewayId": "nat-0fra", "SubnetId": "subnet-0nat"}]},
            "describe_flow_logs": {"FlowLogs": [{
                "FlowLogId": "fl-0abc", "LogDestinationType": "s3",
                "LogDestination": "arn:aws:s3:::lz-woo-ist-residency-123/flow-logs/"}]},
        },
        ("rds", R): {"describe_db_instances": describe_db_instances, "describe_db_snapshots": {"DBSnapshots": [
            {"DBSnapshotArn": arn("rds", "snapshot:rds:lz-woo-test-db-2026-10-30"),
             "DBInstanceIdentifier": "lz-woo-test-db", "TagList": tagset(PERSONAL)},
        ]}},
        ("backup", R): {"list_backup_vaults": {"BackupVaultList": []}},
        ("s3", R): {"get_bucket_location": {"LocationConstraint": R}},
        ("dlm", R): {
            "get_lifecycle_policies": {"Policies": [{"PolicyId": "policy-0db"}]},
            "get_lifecycle_policy": {"Policy": {"State": "ENABLED", "PolicyArn": arn("dlm", "policy/policy-0db"),
                "PolicyDetails": {"PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
                    "TargetTags": [{"Key": "lz-woo-snapshot", "Value": "lz-woo-ist-db"}],
                    "Schedules": [{"Name": "daily-local", "CreateRule": {"Location": "LOCAL_ZONE"}}]}}},
        },
        ("logs", R): {
            "describe_log_groups": {"logGroups": [
                log_group("/ecs/lz-woo-ist-wordpress"),
                log_group("/ecs/lz-woo-ist-exec"),
                log_group("/aws/ecs/containerinsights/lz-woo-ist-cluster/performance"),
            ]},
            "list_tags_for_resource": lambda **kw: {
                "tags": {"data-class": "personal"} if "ecs/lz-woo-ist" in kw["resourceArn"] else {}},
            "filter_log_events": filter_log_events,
        },
        ("ecs", R): ecs_ops(),
        ("athena", R): athena_ops(),
        ("route53resolver", R): {
            "list_resolver_query_log_config_associations": {"ResolverQueryLogConfigAssociations": [
                {"ResolverQueryLogConfigId": "rqlc-1", "Status": "ACTIVE"}]},
            "list_resolver_query_log_configs": {"ResolverQueryLogConfigs": [
                {"Id": "rqlc-1", "DestinationArn": "arn:aws:s3:::lz-woo-ist-residency-123/dns-logs"}]},
        },
    }
    clients.update({(svc, "us-east-1"): ops for svc, ops in empty_region.items()})
    return FakeSession(clients)


@pytest.fixture
def results():
    cfg = Config(
        region=R, local_zone=LZ, local_zone_id="euc1-ist1-az1", vpc_id=VPC,
        athena_workgroup="lz-woo-ist-residency-guard", glue_database="lz_woo_ist_residency",
        flow_logs_table="flow_logs", dns_logs_table="dns_logs", capture_enabled=True, retention_days=3,
        regions=[R, "us-east-1"],
    )
    cfg.validate()
    ctx = Context(
        session=build_session(), config=cfg, account_id=ACCOUNT, regions=[R, "us-east-1"],
        now=datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc), sleep=lambda s: None,
    )
    return run_checks(ctx)


def by_rule(results, rule, status=None):
    return [f for r in results for f in r.findings if f.rule == rule and (status is None or f.status == status)]


def test_no_check_crashed(results):
    assert not [g for r in results if r.crashed for g in r.gaps]


def test_rg001_application_logs(results):
    fails = by_rule(results, "RG-001", Status.FAIL)
    assert [f.resource.split(":")[-1] for f in fails] == ["/ecs/lz-woo-ist-wordpress"]
    assert fails[0].location == R
    assert fails[0].details["hits"] == {"ip": 1, "lines": 1}
    assert by_rule(results, "RG-001", Status.OK)[0].resource == "1 log grubu"


def test_rg002_exec_logs(results):
    (f,) = by_rule(results, "RG-002")
    assert f.status == Status.FAIL and "/ecs/lz-woo-ist-exec" in f.resource
    assert f.details["hits"] == {"email": 1, "tckn": 1, "lines": 1}


def test_rg003_nat_in_parent_az_with_flow_evidence(results):
    (fail,) = by_rule(results, "RG-003", Status.FAIL)
    assert fail.resource == "nat-0fra" and fail.location == "eu-central-1a"
    # app (AMAZON + internet) ve data (apt) subnet'lerinin NAT uzerinden giden genel trafigi
    assert fail.details["egress_bytes_window"] == 5_000_000 + 200_000 + 80_000_000
    assert by_rule(results, "RG-003", Status.OK)[0].resource == "igw-0abc"


def test_rg004_external_calls(results):
    status = {f.resource: f.status for f in by_rule(results, "RG-004")}
    assert status["secure.gravatar.com"] == Status.FAIL
    assert status["api.wordpress.org"] == Status.WARN
    assert status["d111111abcdef8.cloudfront.net"] == Status.WARN
    assert "ecs.eu-central-1.amazonaws.com" not in status


def test_rg005_inventory(results):
    status = {f.resource: (f.status, f.location) for f in by_rule(results, "RG-005")}
    assert status[arn("ec2", "instance/i-0db")] == (Status.OK, LZ)
    assert status[f"arn:aws:ec2:{R}::snapshot/snap-0aaaaaaaaaaaaaaa1"] == (Status.OK, LZ)
    assert status[arn("rds", "db:lz-woo-test-db")] == (Status.FAIL, "eu-central-1a")
    assert status[arn("rds", "snapshot:rds:lz-woo-test-db-2026-10-30")] == (Status.FAIL, R)
    assert status["arn:aws:s3:::lz-woo-ist-static-123"] == (Status.OK, R)
    assert status[arn("kinesis", "stream/orders")][0] == Status.WARN
    assert not any("log-group" in a for a in status)


def test_rg006_untagged_copies_follow_lineage(results):
    status = {f.resource.split("/")[-1]: f.status for f in by_rule(results, "RG-006")}
    assert status == {"snap-0bbbbbbbbbbbbbbb2": Status.FAIL, "snap-0ccccccccccccccc3": Status.FAIL, "snap-0ddddddddddddddd4": Status.WARN}


def test_rg007_baseline_tasks(results):
    status = {(f.resource, f.location): f.status for f in by_rule(results, "RG-007")}
    assert status[("lz-woo-ist-cluster/service:lz-woo-ist-service", LZ)] == Status.OK
    assert status[("lz-woo-test-cluster/service:lz-woo-test-service", "eu-central-1a")] == Status.FAIL


def test_rg008_dlm_local(results):
    (f,) = by_rule(results, "RG-008")
    assert f.status == Status.OK and f.details["volumes"] == ["vol-0data"]


def test_rg009_audit_data_location(results):
    assert {(f.resource, f.status, f.location) for f in by_rule(results, "RG-009")} == {
        ("fl-0abc", Status.WARN, R), ("rqlc-1", Status.WARN, R)}


def test_report(results):
    meta = Meta("once", datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc), ACCOUNT, R, LZ, "euc1-ist1-az1",
                [R, "us-east-1"], 24, 72)
    md = render_markdown(meta, results)
    assert ACCOUNT not in md and "<hesap>" in md
    assert "# Residency Guard raporu: once" in md
    assert "| RG-003 | ❌ | `nat-0fra` | eu-central-1a |" in md
    assert "hukuki görüş değildir" in md
    # Log ornekleminde gecen degerler rapora sizmaz
    assert "85.105.12.34" not in md and "ayse.yilmaz" not in md and "12345678950" not in md
    assert ACCOUNT in render_markdown(meta, results, show_account=True)

    doc = json.loads(render_json(meta, results))
    assert doc["summary"]["fail"] == sum(1 for r in results for f in r.findings if f.status == Status.FAIL)
    assert exit_code(results) == 2
