"""Envanter (RG-005), etiketsiz kopyalar (RG-006) ve yedek politikasi (RG-008).

Konum, bir kaynagin verisinin fiziksel olarak durdugu yerdir: AZ ya da Local
Zone adi (eu-central-1-ist-1a), bolge geneline yayilan servislerde bolge adi
(eu-central-1). Yalnizca Local Zone adi "Turkiye'de" sayilir.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from residency_guard.aws import Context, paginate, tags_to_dict
from residency_guard.model import CheckResult, Status

RESIDENCY_KEY = "data-residency"
CLASS_KEY = "data-class"

# Veri tutmayan, yalnizca yapilandirma/kontrol duzlemi olan kaynak turleri.
# Burada olmayan ve cozulemeyen her tur uyari olarak raporlanir.
CONTROL_SERVICES = {
    "iam", "ecs", "dlm", "events", "application-autoscaling", "cloudformation",
    "cloudfront", "wafv2", "kms", "route53resolver", "glue", "athena", "ssm",
    "elasticloadbalancing", "codebuild", "codepipeline", "ecr", "sns", "budgets",
}
CONTROL_EC2_TYPES = {
    "launch-template", "security-group", "subnet", "vpc", "network-interface",
    "natgateway", "elastic-ip", "route-table", "internet-gateway", "key-pair",
    "vpc-flow-log", "dhcp-options", "network-acl", "prefix-list",
}
# Bolge geneline yayilan veri servisleri: konum = bolge
REGIONAL_DATA_SERVICES = {"rds", "elasticache", "backup", "dynamodb", "secretsmanager", "es", "fsx"}

_SNAP_REF = re.compile(r"snap-[0-9a-f]{8,17}")


def parse_arn(arn: str) -> tuple[str, str, str, str]:
    """(service, region, resource_type, resource_id)"""
    parts = arn.split(":", 5)
    service, region, resource = parts[2], parts[3], parts[5]
    if service == "s3":
        return service, region, "bucket", resource
    m = re.match(r"([^/:]+)[/:](.*)", resource)
    if m:
        return service, region, m.group(1), m.group(2)
    return service, region, resource, resource


def kind(arn: str) -> tuple[str, str]:
    """(service, resource_type), ornegin ("ec2", "volume")"""
    service, _, rtype, _ = parse_arn(arn)
    return service, rtype


def _not_found(exc: Exception) -> bool:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    return "NotFound" in code or code.endswith(".Malformed")


class Resolver:
    """ARN -> konum. None: kaynak artik yok (silinmis, sonlandirilmis)."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.cfg = ctx.config

    def location(self, arn: str) -> str | None:
        service, region, rtype, rid = parse_arn(arn)
        handler: Callable[[str, str], str | None] | None = getattr(
            self, f"_{service.replace('-', '_')}_{rtype.replace('-', '_')}", None
        )
        if handler:
            try:
                return handler(region, rid)
            except Exception as exc:  # noqa: BLE001
                if _not_found(exc):
                    return None
                raise
        if service in REGIONAL_DATA_SERVICES:
            return region
        raise LookupError(f"konum cozucu yok: {service}/{rtype}")

    def _ec2_instance(self, region: str, rid: str) -> str | None:
        res = self.ctx.client("ec2", region).describe_instances(InstanceIds=[rid])["Reservations"]
        if not res:
            return None
        inst = res[0]["Instances"][0]
        if inst["State"]["Name"] in ("terminated", "shutting-down"):
            return None
        return inst["Placement"]["AvailabilityZone"]

    def _ec2_volume(self, region: str, rid: str) -> str | None:
        vols = self.ctx.client("ec2", region).describe_volumes(VolumeIds=[rid])["Volumes"]
        return vols[0]["AvailabilityZone"] if vols else None

    def _ec2_snapshot(self, region: str, rid: str) -> str | None:
        snaps = self.ctx.client("ec2", region).describe_snapshots(SnapshotIds=[rid])["Snapshots"]
        if not snaps:
            return None
        # AvailabilityZone yalnizca Local Zone'da (ya da AZ'de) tutulan yerel
        # snapshot'larda gelir; yoksa snapshot bolgenin S3'undedir.
        return snaps[0].get("AvailabilityZone") or region

    def _ec2_image(self, region: str, rid: str) -> str | None:
        return region

    def _rds_db(self, region: str, rid: str) -> str | None:
        dbs = self.ctx.client("rds", region).describe_db_instances(DBInstanceIdentifier=rid)["DBInstances"]
        if not dbs:
            return None
        return dbs[0].get("AvailabilityZone") or region

    def _elasticfilesystem_file_system(self, region: str, rid: str) -> str | None:
        fss = self.ctx.client("efs", region).describe_file_systems(FileSystemId=rid)["FileSystems"]
        if not fss:
            return None
        return fss[0].get("AvailabilityZoneName") or region

    def _s3_bucket(self, region: str, rid: str) -> str | None:
        # Directory bucket adi zone kimligini tasir: <ad>--euc1-ist1-az1--x-s3
        m = re.fullmatch(r".+--([a-z0-9-]+)--x-s3", rid)
        if m:
            if m.group(1) == self.cfg.local_zone_id:
                return self.cfg.local_zone
            return m.group(1)
        loc = self.ctx.client("s3", self.cfg.region).get_bucket_location(Bucket=rid).get("LocationConstraint")
        return {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(loc, loc)

    def _autoscaling_autoScalingGroup(self, region: str, rid: str) -> str | None:
        name = rid.split("autoScalingGroupName/")[-1]
        groups = self.ctx.client("autoscaling", region).describe_auto_scaling_groups(
            AutoScalingGroupNames=[name]
        )["AutoScalingGroups"]
        if not groups:
            return None
        subnets = [s for s in groups[0].get("VPCZoneIdentifier", "").split(",") if s]
        if not subnets:
            return ",".join(sorted(groups[0].get("AvailabilityZones", []))) or region
        found = self.ctx.client("ec2", region).describe_subnets(SubnetIds=subnets)["Subnets"]
        return ",".join(sorted({s["AvailabilityZone"] for s in found}))


def _is_control(service: str, rtype: str) -> bool:
    if service == "ec2":
        return rtype in CONTROL_EC2_TYPES
    return service in CONTROL_SERVICES


def check_inventory(ctx: Context) -> CheckResult:
    """RG-005: data-residency etiketli her kaynagin konumu, tum bolgelerde."""
    cfg = ctx.config
    result = CheckResult("Envanter")
    resolver = Resolver(ctx)
    tagged: dict[str, dict[str, str]] = {}

    for region in ctx.regions:
        try:
            resources = list(
                paginate(
                    ctx.client("resourcegroupstaggingapi", region),
                    "get_resources",
                    "ResourceTagMappingList",
                    TagFilters=[{"Key": RESIDENCY_KEY, "Values": [cfg.residency_value]}],
                )
            )
        except Exception as exc:  # noqa: BLE001
            result.gaps.append(f"{region}: etiket envanteri okunamadı ({type(exc).__name__}: {exc})")
            continue
        for res in resources:
            tagged[res["ResourceARN"]] = tags_to_dict(res.get("Tags"))

    personal: dict[str, dict[str, str]] = {}
    for arn, tags in sorted(tagged.items()):
        service, _, rtype, rid = parse_arn(arn)
        data_class = tags.get(CLASS_KEY)
        if data_class == "personal":
            personal[arn] = tags
        if service == "logs":
            continue  # RG-001/RG-002: log gruplari icerikleriyle birlikte orada denetlenir
        if _is_control(service, rtype):
            result.add("RG-005", Status.OK, arn, "-", "Yapılandırma / kontrol düzlemi; veri saklamaz")
            continue
        try:
            location = resolver.location(arn)
        except LookupError:
            result.add(
                "RG-005", Status.WARN, arn, "?",
                f"Konumu çözülemeyen kaynak türü ({service}/{rtype}); elle kontrol edin",
                {"data_class": data_class},
            )
            continue
        except Exception as exc:  # noqa: BLE001
            result.add("RG-005", Status.WARN, arn, "?", f"Konum okunamadı: {type(exc).__name__}")
            continue
        if location is None:
            continue  # silinmis/sonlandirilmis; etiket API'si bir sure daha listeler

        details = {"data_class": data_class, "type": f"{service}/{rtype}"}
        if location == cfg.local_zone:
            result.add("RG-005", Status.OK, arn, location, "Local Zone'da", details)
        elif data_class == "personal":
            result.add("RG-005", Status.FAIL, arn, location, "Kişisel veri Local Zone dışında", details)
        elif data_class == "non-personal":
            result.add(
                "RG-005", Status.OK, arn, location,
                "Local Zone dışında ama kişisel veri değil (data-class=non-personal)", details,
            )
        else:
            result.add(
                "RG-005", Status.WARN, arn, location,
                "Local Zone dışında ve data-class etiketi yok", details,
            )

    ctx.shared["tagged_arns"] = set(tagged)
    ctx.shared["personal_arns"] = personal
    return result


def check_copies(ctx: Context) -> CheckResult:
    """RG-006: data-residency etiketi tasimayan snapshot ve recovery point'ler.

    Etiketliler RG-005'te zaten var. Burada etiketi kopyalanmamis (elle alinmis,
    baska bolgeye kopyalanmis) kopyalar aranir; kisisel bir kaynaga
    baglanabiliyorsa hata, baglanamiyorsa uyari.
    """
    cfg = ctx.config
    result = CheckResult("Etiketsiz kopyalar")
    tagged: set[str] = ctx.shared.get("tagged_arns", set())
    personal: dict[str, dict[str, str]] = ctx.shared.get("personal_arns", {})

    personal_ids = {parse_arn(a)[3] for a in personal}
    personal_db_ids = {parse_arn(a)[3] for a in personal if kind(a) == ("rds", "db")}
    reported: set[str] = set()

    # --- EBS snapshot'lari: soy agaci uzerinden kisisel veri ---
    snapshots: list[tuple[str, dict[str, Any]]] = []
    for region in ctx.regions:
        try:
            for snap in paginate(ctx.client("ec2", region), "describe_snapshots", "Snapshots", OwnerIds=["self"]):
                snapshots.append((region, snap))
        except Exception as exc:  # noqa: BLE001
            result.gaps.append(f"{region}: EBS snapshot'ları okunamadı ({type(exc).__name__})")

    lineage_ids = set(personal_ids)
    lineage_keys = {
        s["DataEncryptionKeyId"]
        for _, s in snapshots
        if s["SnapshotId"] in personal_ids and s.get("DataEncryptionKeyId")
    }
    changed = True
    while changed:
        changed = False
        for _, s in snapshots:
            if s["SnapshotId"] in lineage_ids:
                continue
            refs = set(_SNAP_REF.findall(s.get("Description", "")))
            if (
                s.get("VolumeId") in lineage_ids
                or (s.get("DataEncryptionKeyId") and s["DataEncryptionKeyId"] in lineage_keys)
                or refs & lineage_ids
            ):
                lineage_ids.add(s["SnapshotId"])
                if s.get("DataEncryptionKeyId"):
                    lineage_keys.add(s["DataEncryptionKeyId"])
                changed = True

    tagged_snapshot_ids = {parse_arn(a)[3] for a in tagged if kind(a) == ("ec2", "snapshot")}
    for region, s in snapshots:
        arn = f"arn:aws:ec2:{region}::snapshot/{s['SnapshotId']}"
        if s["SnapshotId"] in tagged_snapshot_ids or RESIDENCY_KEY in tags_to_dict(s.get("Tags")):
            continue
        location = s.get("AvailabilityZone") or region
        if location == cfg.local_zone:
            continue
        reported.add(arn)
        details = {"volume": s.get("VolumeId"), "description": s.get("Description", "")[:120]}
        if s["SnapshotId"] in lineage_ids:
            result.add("RG-006", Status.FAIL, arn, location, "Kişisel veri diskinin etiketsiz kopyası", details)
        else:
            result.add(
                "RG-006", Status.WARN, arn, location,
                "Etiketsiz EBS snapshot'ı, kaynağı bilinmiyor; içeriği kontrol edin", details,
            )

    # --- RDS snapshot'lari (elle, otomatik, AWS Backup) ---
    for region in ctx.regions:
        try:
            db_snaps = list(paginate(ctx.client("rds", region), "describe_db_snapshots", "DBSnapshots"))
        except Exception as exc:  # noqa: BLE001
            result.gaps.append(f"{region}: RDS snapshot'ları okunamadı ({type(exc).__name__})")
            continue
        for s in db_snaps:
            arn = s["DBSnapshotArn"]
            if arn in tagged or RESIDENCY_KEY in tags_to_dict(s.get("TagList")):
                continue
            reported.add(arn)
            details = {"db": s.get("DBInstanceIdentifier"), "type": s.get("SnapshotType")}
            if s.get("DBInstanceIdentifier") in personal_db_ids:
                result.add("RG-006", Status.FAIL, arn, region, "Kişisel veri tutan RDS'in etiketsiz snapshot'ı", details)
            else:
                result.add("RG-006", Status.WARN, arn, region, "Etiketsiz RDS snapshot'ı; içeriği kontrol edin", details)

    # --- AWS Backup recovery point'leri ---
    for region in ctx.regions:
        backup = ctx.client("backup", region)
        try:
            vaults = list(paginate(backup, "list_backup_vaults", "BackupVaultList"))
        except Exception as exc:  # noqa: BLE001
            result.gaps.append(f"{region}: AWS Backup vault'ları okunamadı ({type(exc).__name__})")
            continue
        for vault in vaults:
            points = paginate(
                backup, "list_recovery_points_by_backup_vault", "RecoveryPoints",
                BackupVaultName=vault["BackupVaultName"],
            )
            for rp in points:
                arn = rp["RecoveryPointArn"]
                if arn in tagged or arn in reported:
                    continue
                source = rp.get("ResourceArn", "")
                details = {"vault": vault["BackupVaultName"], "source": source}
                if source and (source in personal or parse_arn(source)[3] in personal_ids):
                    result.add("RG-006", Status.FAIL, arn, region, "Kişisel veri kaynağının etiketsiz yedeği", details)
                else:
                    result.add("RG-006", Status.WARN, arn, region, "Etiketsiz recovery point; içeriği kontrol edin", details)

    if not result.findings:
        result.add("RG-006", Status.OK, "-", "-", "Local Zone dışında etiketsiz snapshot veya recovery point yok")
    return result


def check_backup_policies(ctx: Context) -> CheckResult:
    """RG-008: kisisel diskleri hedefleyen DLM politikalari snapshot'i nereye yaziyor."""
    cfg = ctx.config
    result = CheckResult("Yedek politikası")
    personal = ctx.shared.get("personal_arns", {})
    volume_tags = {
        parse_arn(arn)[3]: tags for arn, tags in personal.items() if kind(arn) == ("ec2", "volume")
    }

    dlm = ctx.client("dlm")
    covered: set[str] = set()
    for summary in dlm.get_lifecycle_policies().get("Policies", []):
        policy = dlm.get_lifecycle_policy(PolicyId=summary["PolicyId"])["Policy"]
        details = policy.get("PolicyDetails", {})
        if details.get("PolicyType", "EBS_SNAPSHOT_MANAGEMENT") != "EBS_SNAPSHOT_MANAGEMENT":
            continue
        targets = {(t["Key"], t["Value"]) for t in details.get("TargetTags", [])}
        hits = sorted(v for v, tags in volume_tags.items() if targets & set(tags.items()))
        if not hits:
            continue
        covered.update(hits)
        resource = policy.get("PolicyArn") or summary["PolicyId"]
        if policy.get("State") != "ENABLED":
            result.add("RG-008", Status.WARN, resource, cfg.region, "Kişisel diskleri hedefleyen politika kapalı", {"volumes": hits})
            continue
        for schedule in details.get("Schedules", []):
            where = schedule.get("CreateRule", {}).get("Location", "CLOUD")
            info = {"schedule": schedule.get("Name"), "location": where, "volumes": hits}
            if schedule.get("CrossRegionCopyRules"):
                result.add("RG-008", Status.FAIL, resource, cfg.region, "Snapshot'lar başka bölgeye kopyalanıyor", info)
            elif where != "LOCAL_ZONE":
                result.add(
                    "RG-008", Status.FAIL, resource, cfg.region,
                    f"Snapshot'lar {where} konumuna yazılıyor (parent region)", info,
                )
            else:
                result.add("RG-008", Status.OK, resource, cfg.local_zone, "Snapshot'lar Local Zone'da (LOCAL_ZONE)", info)

    if not covered and volume_tags:
        result.gaps.append("Kişisel etiketli EBS disklerini hedefleyen bir DLM politikası bulunamadı")
    return result
