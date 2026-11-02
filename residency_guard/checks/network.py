"""Ag: NAT'in konumu (RG-003), Flow Logs ile LZ'den cikan trafik ve denetim
verisinin konumu (RG-009).

NAT kontrolu yapilandirmaya bakar (route table -> NAT -> subnet -> AZ); akis
olcumu bunun kanitini bayt olarak ekler. Akis verisi yoksa RG-003 yine calisir.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import timedelta
from typing import Any

from residency_guard.aws import Context, athena_query, paginate, tags_to_dict
from residency_guard.model import CheckResult, Section, Status
from residency_guard.report import human_bytes


def vpc_layout(ctx: Context) -> dict[str, Any]:
    """Subnet'ler, CIDR'ler ve her subnet'in varsayilan cikisi."""
    cfg = ctx.config
    ec2 = ctx.client("ec2")
    vpc_filter = [{"Name": "vpc-id", "Values": [cfg.vpc_id]}]

    vpc = ec2.describe_vpcs(VpcIds=[cfg.vpc_id])["Vpcs"][0]
    vpc_cidrs = [a["CidrBlock"] for a in vpc.get("CidrBlockAssociationSet", [])] or [vpc["CidrBlock"]]

    subnets: dict[str, dict[str, Any]] = {}
    for s in paginate(ec2, "describe_subnets", "Subnets", Filters=vpc_filter):
        subnets[s["SubnetId"]] = {
            "az": s["AvailabilityZone"],
            "cidr": s["CidrBlock"],
            "name": tags_to_dict(s.get("Tags")).get("Name", s["SubnetId"]),
            "in_lz": s["AvailabilityZone"] == cfg.local_zone,
        }

    main_table: dict[str, Any] | None = None
    explicit: dict[str, dict[str, Any]] = {}
    for rt in paginate(ec2, "describe_route_tables", "RouteTables", Filters=vpc_filter):
        for assoc in rt.get("Associations", []):
            if assoc.get("Main"):
                main_table = rt
            elif assoc.get("SubnetId"):
                explicit[assoc["SubnetId"]] = rt

    nat_ids: set[str] = set()
    for sid, info in subnets.items():
        rt = explicit.get(sid, main_table) or {}
        default = next((r for r in rt.get("Routes", []) if r.get("DestinationCidrBlock") == "0.0.0.0/0"), {})
        if default.get("NatGatewayId"):
            info["egress"] = ("nat", default["NatGatewayId"])
            nat_ids.add(default["NatGatewayId"])
        elif default.get("GatewayId", "").startswith("igw-"):
            info["egress"] = ("igw", default["GatewayId"])
        else:
            info["egress"] = ("none", None)

    nats: dict[str, dict[str, Any]] = {}
    if nat_ids:
        for nat in ec2.describe_nat_gateways(NatGatewayIds=sorted(nat_ids))["NatGateways"]:
            subnet = subnets.get(nat.get("SubnetId", ""), {})
            nats[nat["NatGatewayId"]] = {"subnet": nat.get("SubnetId"), "az": subnet.get("az", "?")}

    return {"vpc_cidrs": vpc_cidrs, "subnets": subnets, "nats": nats}


def check_network(ctx: Context) -> CheckResult:
    cfg = ctx.config
    result = CheckResult("Ağ çıkışı")
    if not cfg.vpc_id:
        result.gaps.append("vpc_id verilmedi; NAT ve akış kontrolleri atlandı")
        return result

    layout = vpc_layout(ctx)
    ctx.shared["vpc_layout"] = layout
    lz_subnets = {sid: s for sid, s in layout["subnets"].items() if s["in_lz"]}
    if not lz_subnets:
        result.gaps.append(f"{cfg.vpc_id} içinde {cfg.local_zone} subnet'i yok")
        return result

    by_nat: dict[str, list[str]] = defaultdict(list)
    for sid, s in sorted(lz_subnets.items(), key=lambda kv: kv[1]["name"]):
        kind, target = s["egress"]
        if kind == "nat":
            by_nat[target].append(s["name"])
        elif kind == "igw":
            result.add(
                "RG-003", Status.OK, target, cfg.local_zone,
                f"{s['name']}: Local Zone'un kendi internet çıkışı (IGW)",
            )

    nat_findings = {}
    for nat_id, names in by_nat.items():
        az = layout["nats"].get(nat_id, {}).get("az", "?")
        details = {"subnets": names}
        if az == cfg.local_zone:
            nat_findings[nat_id] = result.add(
                "RG-003", Status.OK, nat_id, az, f"{', '.join(names)}: NAT Local Zone'da", details
            )
        else:
            nat_findings[nat_id] = result.add(
                "RG-003", Status.FAIL, nat_id, az,
                f"{', '.join(names)}: internet ve AWS API trafiği {az} (Frankfurt) üzerinden çıkıyor",
                details,
            )

    if cfg.athena_ready and cfg.flow_logs_table:
        try:
            _flows(ctx, result, layout, lz_subnets, nat_findings)
        except Exception as exc:  # noqa: BLE001
            result.gaps.append(f"Akış sorgusu çalışmadı ({type(exc).__name__}: {exc})")
    else:
        result.gaps.append("Athena ayarları yok; Flow Logs ile akış ölçümü atlandı")
    return result


def _flows(
    ctx: Context,
    result: CheckResult,
    layout: dict[str, Any],
    lz_subnets: dict[str, dict[str, Any]],
    nat_findings: dict[str, Any],
) -> None:
    cfg = ctx.config
    start = ctx.now - timedelta(hours=cfg.window_hours)
    subnet_list = ", ".join(f"'{sid}'" for sid in sorted(lz_subnets))
    sql = f"""
SELECT subnet_id, dstaddr, coalesce(pkt_dst_aws_service, '-') AS service,
       sum(bytes) AS bytes, sum(packets) AS packets
FROM "{cfg.glue_database}"."{cfg.flow_logs_table}"
WHERE date >= '{start:%Y/%m/%d}'
  AND start >= {int(start.timestamp())}
  AND vpc_id = '{cfg.vpc_id}'
  AND flow_direction = 'egress'
  AND action = 'ACCEPT'
  AND subnet_id IN ({subnet_list})
GROUP BY 1, 2, 3
ORDER BY bytes DESC
LIMIT 20000
""".strip()
    rows = athena_query(ctx, sql)
    if not rows:
        result.gaps.append(
            f"Son {cfg.window_hours} saatte akış kaydı yok (kayıt kapalı, trafik yok ya da Flow Logs henüz S3'e düşmedi: ~10 dk)"
        )
        return

    lz_nets = [ipaddress.ip_network(s["cidr"]) for s in lz_subnets.values()]
    vpc_nets = [ipaddress.ip_network(c) for c in layout["vpc_cidrs"]]

    totals: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0])
    nat_bytes: dict[str, int] = defaultdict(int)
    top_public: dict[tuple[str, str, str], int] = defaultdict(int)
    for row in rows:
        subnet = lz_subnets.get(row["subnet_id"] or "")
        if not subnet:
            continue
        try:
            dst = ipaddress.ip_address(row["dstaddr"] or "")
        except ValueError:
            continue
        nbytes, npackets = int(row["bytes"] or 0), int(row["packets"] or 0)
        service = row["service"] if row["service"] not in (None, "", "-") else "internet"

        if any(dst in n for n in lz_nets):
            target = "Local Zone içi"
            service = "-"
        elif any(dst in n for n in vpc_nets):
            target = "VPC içi, Local Zone dışı subnet"
            service = "-"
        elif not dst.is_global:
            target = "Özel / link-local adres"
            service = "-"
        else:
            kind, gw = subnet["egress"]
            if kind == "nat":
                az = layout["nats"].get(gw, {}).get("az", "?")
                target = f"NAT üzerinden ({az})"
                nat_bytes[gw] += nbytes
            else:
                target = "Local Zone IGW üzerinden"
            top_public[(target, str(dst), service)] += nbytes

        t = totals[(subnet["name"], target, service)]
        t[0] += nbytes
        t[1] += npackets

    for nat_id, nbytes in nat_bytes.items():
        if nat_id in nat_findings:
            nat_findings[nat_id].details["egress_bytes_window"] = nbytes

    result.sections.append(
        Section(
            title=f"Local Zone subnet'lerinden çıkan trafik (son {cfg.window_hours} saat)",
            columns=["Kaynak subnet", "Hedef", "AWS servisi", "Bayt", "Paket"],
            rows=[
                [src, target, service, human_bytes(b), p]
                for (src, target, service), (b, p) in sorted(totals.items(), key=lambda kv: -kv[1][0])
            ],
            note=(
                "Yalnızca kabul edilen egress kayıtları. 'AWS servisi' Flow Logs'un pkt-dst-aws-service alanı; "
                "boşsa hedef AWS dışı bir internet adresidir. AWS API trafiği (ECR, SSM, ECS) kontrol "
                "trafiğidir; kişisel veri taşımaz ama NAT Frankfurt'taysa oradan geçer."
            ),
        )
    )
    result.sections.append(
        Section(
            title="En çok veri gönderilen genel adresler",
            columns=["Yol", "Hedef adres", "AWS servisi", "Bayt"],
            rows=[
                [target, dst, service, human_bytes(b)]
                for (target, dst, service), b in sorted(top_public.items(), key=lambda kv: -kv[1])[:15]
            ],
        )
    )


def _bucket_location(ctx: Context, bucket: str) -> str:
    loc = ctx.client("s3").get_bucket_location(Bucket=bucket).get("LocationConstraint")
    return {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(loc, loc)


def _destination_location(ctx: Context, destination: str) -> str:
    # arn:aws:s3:::bucket/prefix  |  arn:aws:logs:region:acct:log-group:...
    parts = destination.split(":")
    if len(parts) > 5 and parts[2] == "s3":
        return _bucket_location(ctx, parts[5].split("/")[0])
    if len(parts) > 3 and parts[3]:
        return parts[3]
    return ctx.config.region


def check_audit_data(ctx: Context) -> CheckResult:
    """RG-009: Flow Logs ve DNS sorgu loglari da IP icerir; nerede durduklari rapora girer."""
    cfg = ctx.config
    result = CheckResult("Denetim verisi")
    if not cfg.vpc_id:
        return result

    retention = f"{cfg.retention_days} gün sonra silinir" if cfg.retention_days else "saklama süresi bilinmiyor"
    ec2 = ctx.client("ec2")
    flow_logs = ec2.describe_flow_logs(Filter=[{"Name": "resource-id", "Values": [cfg.vpc_id]}])["FlowLogs"]
    for fl in flow_logs:
        dest = fl.get("LogDestination") or fl.get("LogGroupName", "")
        where = _destination_location(ctx, dest) if dest else cfg.region
        result.add(
            "RG-009", Status.WARN, fl["FlowLogId"], where,
            f"VPC Flow Logs IP adresi içerir ve Local Zone dışında ({fl.get('LogDestinationType')}); {retention}",
            {"destination": dest},
        )

    resolver = ctx.client("route53resolver")
    assocs = list(
        paginate(
            resolver, "list_resolver_query_log_config_associations", "ResolverQueryLogConfigAssociations",
            Filters=[{"Name": "ResourceId", "Values": [cfg.vpc_id]}],
        )
    )
    config_ids = {a["ResolverQueryLogConfigId"] for a in assocs if a.get("Status") in ("ACTIVE", "CREATING")}
    if config_ids:
        for qlc in paginate(resolver, "list_resolver_query_log_configs", "ResolverQueryLogConfigs"):
            if qlc["Id"] not in config_ids:
                continue
            dest = qlc.get("DestinationArn", "")
            result.add(
                "RG-009", Status.WARN, qlc["Id"], _destination_location(ctx, dest),
                f"DNS sorgu logları istemci IP'si içerir ve Local Zone dışında; {retention}",
                {"destination": dest},
            )

    if not result.findings:
        result.add("RG-009", Status.OK, cfg.vpc_id, "-", "VPC'de açık Flow Logs veya DNS sorgu logu yok")
    return result
