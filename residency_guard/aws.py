"""AWS erisimi: oturum, rol ustlenme, sayfalama ve Athena sorgusu.

Kontroller boto3'u dogrudan degil Context uzerinden kullanir; testler ayni
arayuzu sahte istemcilerle saglar.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator

from residency_guard.config import Config


@dataclass
class Context:
    session: Any
    config: Config
    account_id: str
    regions: list[str]
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sleep: Callable[[float], None] = time.sleep
    # Kontroller arasi paylasilan bilgi (ornegin envanterin buldugu kisisel kaynaklar)
    shared: dict[str, Any] = field(default_factory=dict)
    _clients: dict[tuple[str, str], Any] = field(default_factory=dict)

    def client(self, service: str, region: str | None = None) -> Any:
        key = (service, region or self.config.region)
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=key[1])
        return self._clients[key]

    @property
    def log_regions(self) -> list[str]:
        return self.config.log_regions or [self.config.region]


def paginate(client: Any, operation: str, result_key: str, **kwargs: Any) -> Iterator[Any]:
    if client.can_paginate(operation):
        for page in client.get_paginator(operation).paginate(**kwargs):
            yield from page.get(result_key, [])
    else:
        yield from getattr(client, operation)(**kwargs).get(result_key, [])


def tags_to_dict(tags: list[dict[str, str]] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in tags or []}


def build_session(config: Config, profile: str | None, assume_role: bool) -> tuple[Any, str]:
    import boto3

    base = boto3.Session(profile_name=profile, region_name=config.region)
    if assume_role and config.role_arn:
        creds = base.client("sts").assume_role(
            RoleArn=config.role_arn, RoleSessionName="residency-guard", DurationSeconds=3600
        )["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=config.region,
        )
    else:
        session = base
    account_id = session.client("sts").get_caller_identity()["Account"]
    return session, account_id


def resolve_regions(session: Any, config: Config) -> list[str]:
    if config.regions != "all":
        regions = list(config.regions)
    else:
        ec2 = session.client("ec2", region_name=config.region)
        regions = sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])
    if config.region not in regions:
        regions.insert(0, config.region)
    return regions


class AthenaError(RuntimeError):
    pass


def athena_query(ctx: Context, sql: str, timeout_s: float = 300) -> list[dict[str, str | None]]:
    cfg = ctx.config
    athena = ctx.client("athena")
    qid = athena.start_query_execution(
        QueryString=sql,
        WorkGroup=cfg.athena_workgroup,
        QueryExecutionContext={"Database": cfg.glue_database},
    )["QueryExecutionId"]

    waited, delay = 0.0, 1.0
    while True:
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        state = status["State"]
        if state == "SUCCEEDED":
            break
        if state in ("FAILED", "CANCELLED"):
            raise AthenaError(f"Athena sorgusu {state}: {status.get('StateChangeReason', '')}")
        if waited >= timeout_s:
            athena.stop_query_execution(QueryExecutionId=qid)
            raise AthenaError(f"Athena sorgusu {timeout_s:.0f} sn icinde bitmedi")
        ctx.sleep(delay)
        waited += delay
        delay = min(delay * 2, 10.0)

    rows: list[dict[str, str | None]] = []
    header: list[str] | None = None
    token: str | None = None
    while True:
        kwargs: dict[str, Any] = {"QueryExecutionId": qid, "MaxResults": 1000}
        if token:
            kwargs["NextToken"] = token
        page = athena.get_query_results(**kwargs)
        for row in page["ResultSet"]["Rows"]:
            values = [d.get("VarCharValue") for d in row["Data"]]
            if header is None:
                header = [v or "" for v in values]
                continue
            rows.append(dict(zip(header, values)))
        token = page.get("NextToken")
        if not token:
            return rows
