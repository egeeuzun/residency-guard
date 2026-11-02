import json

import pytest

from residency_guard import pii
from residency_guard.checks.dns import classify
from residency_guard.checks.inventory import parse_arn
from residency_guard.config import Config
from residency_guard.model import CheckResult
from residency_guard.report import exit_code


@pytest.mark.parametrize(
    "value, valid",
    [("12345678950", True), ("12345678951", False), ("02345678950", False), ("1234567895", False)],
)
def test_tckn_checksum(value, valid):
    assert pii.is_valid_tckn(value) is valid


def test_scan_counts_only_public_ips_and_valid_tckn():
    hits = pii.scan([
        "10.1.1.5 172.16.0.1 192.168.1.1 127.0.0.1",  # ozel adresler
        "client=85.105.12.34 version=6.8.1",  # 1 genel IP
        "order 12345678950 ts=1730000000000 id=12345678951",  # 1 gecerli TCKN
        "mail: demo.musteri@example.com",
    ])
    assert hits == {"ip": 1, "tckn": 1, "email": 1, "lines": 3}
    assert pii.describe(hits) == "1 IP, 1 e-posta, 1 TCKN"
    assert pii.describe(pii.scan(["temiz satir"])) == "desen yok"


@pytest.mark.parametrize(
    "name, cls",
    [
        ("ssm.eu-central-1.amazonaws.com.", "aws"),
        ("ip-10-1-10-5.eu-central-1.compute.internal", "aws"),
        ("secure.gravatar.com", "sharing"),
        ("rest.akismet.com", "sharing"),
        ("api.wordpress.org", "external"),
        ("notwordpress.org", "external"),
        ("security.ubuntu.com", "os"),
        ("d1.cloudfront.net", "cdn"),
    ],
)
def test_dns_classify(name, cls):
    assert classify(name)[0] == cls


def test_parse_arn():
    assert parse_arn("arn:aws:rds:eu-central-1:1:db:mydb") == ("rds", "eu-central-1", "db", "mydb")
    assert parse_arn("arn:aws:ec2:eu-central-1:1:volume/vol-1") == ("ec2", "eu-central-1", "volume", "vol-1")
    assert parse_arn("arn:aws:s3:::bucket-a") == ("s3", "", "bucket", "bucket-a")
    assert parse_arn("arn:aws:logs:eu-central-1:1:log-group:/ecs/x")[2:] == ("log-group", "/ecs/x")


def test_config_from_terraform_output(tmp_path):
    out = {"residency_guard": {"sensitive": False, "value": {
        "region": "eu-central-1", "local_zone": "eu-central-1-ist-1a", "vpc_id": "vpc-0123456789abcdef0",
        "glue_database": "lz_woo_ist_residency", "role_arn": None,
    }}}
    path = tmp_path / "guard.json"
    path.write_text(json.dumps(out))
    cfg = Config.load(path, window_hours=6)
    assert cfg.vpc_id == "vpc-0123456789abcdef0" and cfg.window_hours == 6 and cfg.role_arn is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"vpc_id": "vpc-1' OR '1'='1"},
        {"glue_database": "db; DROP TABLE x"},
        {"local_zone": "eu-central-1a"},
        {"local_zone": "eu-west-1-ist-1a"},
    ],
)
def test_config_rejects_values_that_reach_sql(overrides):
    with pytest.raises(ValueError):
        Config(**overrides).validate()


def test_config_rejects_unknown_keys(tmp_path):
    path = tmp_path / "guard.json"
    path.write_text(json.dumps({"vpcid": "vpc-0123456789abcdef0"}))
    with pytest.raises(ValueError, match="vpcid"):
        Config.load(path)


def test_exit_code_marks_crashed_check():
    assert exit_code([CheckResult("x")]) == 0
    assert exit_code([CheckResult("x", crashed=True)]) == 1


def test_flow_destinations_matched_without_dns():
    from residency_guard.checks.dns import match_destinations

    rows = [
        {"dstaddr": "192.0.76.3", "dstport": "443", "bytes": "9092"},
        {"dstaddr": "66.6.42.251", "dstport": "443", "bytes": "5606"},
        {"dstaddr": "192.0.99.9", "dstport": "443", "bytes": "10"},
        {"dstaddr": "146.75.122.132", "dstport": "80", "bytes": "57492"},
        {"dstaddr": "10.1.20.10", "dstport": "3306", "bytes": "999999"},  # ozel adres
    ]
    forward = {"192.0.76.3": "stats.wp.com"}
    reverse = {"66.6.42.251": "api.wordpress.org"}.get
    out = {ip: (port, name, how) for ip, port, name, how, _ in match_destinations(rows, forward, reverse)}
    assert "10.1.20.10" not in out
    assert out["192.0.76.3"] == (443, "stats.wp.com", "ad çözümleme")
    assert out["66.6.42.251"] == (443, "api.wordpress.org", "ters DNS")
    assert out["192.0.99.9"][1] is None and out["192.0.99.9"][2].startswith("Automattic")
    assert out["146.75.122.132"] == (80, None, "eşleşmedi")
