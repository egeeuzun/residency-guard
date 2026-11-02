"""Sahte istemcilere yapilan her cagri gercek AWS API modelinde var mi?

Senaryo testi gecse de islem ya da parametre adinda bir yazim hatasi gercek
hesapta kirilir. botocore'un servis modeli kimlik bilgisi istemeden bunu
yakalar.
"""

import boto3

from residency_guard.aws import Context
from residency_guard.checks import run_checks
from tests import test_scenario as scenario


def test_every_call_matches_botocore_model():
    session = scenario.build_session()
    cfg = scenario.Config(
        region=scenario.R, local_zone=scenario.LZ, local_zone_id="euc1-ist1-az1", vpc_id=scenario.VPC,
        athena_workgroup="lz-woo-ist-residency-guard", glue_database="lz_woo_ist_residency",
        flow_logs_table="flow_logs", dns_logs_table="dns_logs",
    )
    ctx = Context(session=session, config=cfg, account_id=scenario.ACCOUNT,
                  regions=[scenario.R, "us-east-1"], sleep=lambda s: None)
    run_checks(ctx)

    checked = 0
    for (service, region), fake in session.made.items():
        real = boto3.client(service, region_name=region or scenario.R,
                            aws_access_key_id="x", aws_secret_access_key="x")
        for op, kwargs in fake.calls:
            api_name = real.meta.method_to_api_mapping.get(op)
            assert api_name, f"{service}.{op} boto3'te yok"
            members = real.meta.service_model.operation_model(api_name).input_shape.members
            unknown = set(kwargs) - set(members)
            assert not unknown, f"{service}.{op}: bilinmeyen parametre(ler) {unknown}"
            # Sayfalanan islemlerde gercek istemci paginator kullanir
            checked += 1
    assert checked > 30
