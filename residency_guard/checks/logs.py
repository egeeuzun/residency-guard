"""CloudWatch log gruplari (RG-001, RG-002).

CloudWatch Logs bolgesel bir servistir; Local Zone'da log grubu olmaz. Bu
yuzden kisisel veri tasiyan her log grubu Local Zone disindadir. Kisisel veri
tasidigini iki yoldan anlariz: data-class=personal etiketi ya da ornek
satirlarda IP / e-posta / TCKN deseni. Eslesen degerler rapora yazilmaz.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from residency_guard import pii
from residency_guard.aws import Context, paginate
from residency_guard.model import CheckResult, Status


def exec_log_groups(ctx: Context, region: str) -> dict[str, str]:
    """ECS Exec oturum ciktilarinin yazildigi log gruplari -> cluster adi."""
    ecs = ctx.client("ecs", region)
    arns = list(paginate(ecs, "list_clusters", "clusterArns"))
    groups: dict[str, str] = {}
    for i in range(0, len(arns), 100):
        clusters = ecs.describe_clusters(clusters=arns[i : i + 100], include=["CONFIGURATIONS"])["clusters"]
        for cluster in clusters:
            exec_cfg = cluster.get("configuration", {}).get("executeCommandConfiguration", {})
            group = exec_cfg.get("logConfiguration", {}).get("cloudWatchLogGroupName")
            if group and exec_cfg.get("logging") != "NONE":
                groups[group] = cluster["clusterName"]
    return groups


def _sample(ctx: Context, region: str, group: str) -> list[str]:
    cfg = ctx.config
    start = int((ctx.now - timedelta(hours=cfg.log_lookback_hours)).timestamp() * 1000)
    logs = ctx.client("logs", region)
    lines: list[str] = []
    token: str | None = None
    while len(lines) < cfg.log_max_events:
        kwargs: dict[str, Any] = {
            "logGroupName": group,
            "startTime": start,
            "limit": min(1000, cfg.log_max_events - len(lines)),
        }
        if token:
            kwargs["nextToken"] = token
        page = logs.filter_log_events(**kwargs)
        lines.extend(e.get("message", "") for e in page.get("events", []))
        token = page.get("nextToken")
        if not token:
            break
    return lines


def check_logs(ctx: Context) -> CheckResult:
    cfg = ctx.config
    result = CheckResult("CloudWatch Logs")

    for region in ctx.log_regions:
        logs = ctx.client("logs", region)
        try:
            exec_groups = exec_log_groups(ctx, region)
        except Exception as exc:  # noqa: BLE001
            exec_groups = {}
            result.gaps.append(f"{region}: ECS Exec log ayarı okunamadı ({type(exc).__name__})")

        clean = 0
        for group in paginate(logs, "describe_log_groups", "logGroups"):
            name = group["logGroupName"]
            arn = group.get("logGroupArn") or group["arn"].removesuffix(":*")
            try:
                tags = logs.list_tags_for_resource(resourceArn=arn).get("tags", {})
            except Exception:  # noqa: BLE001
                tags = {}
            personal_tag = tags.get("data-class") == "personal"

            # storedBytes'a bakma: yeni gruplarda saatlerce 0 kalir.
            hits = pii.scan([])
            sampled = 0
            try:
                lines = _sample(ctx, region, name)
                sampled = len(lines)
                hits = pii.scan(lines)
            except Exception as exc:  # noqa: BLE001
                result.gaps.append(f"{name}: örnek satır okunamadı ({type(exc).__name__})")

            details = {
                "sampled_events": sampled,
                "hits": dict(hits),
                "data_class": tags.get("data-class"),
                "retention_days": group.get("retentionInDays"),
            }
            found = pii.describe(hits) if sampled else "örnek satır yok"

            if name in exec_groups:
                result.add(
                    "RG-002", Status.FAIL, arn, region,
                    f"ECS Exec oturum çıktıları ({exec_groups[name]}) bu gruba yazılıyor; "
                    f"örneklemde: {found}",
                    details,
                )
            elif hits or personal_tag:
                reason = f"örneklemde {found}" if hits else "data-class=personal etiketli"
                result.add("RG-001", Status.FAIL, arn, region, f"Kişisel veri içeren log grubu: {reason}", details)
            else:
                clean += 1

        if clean:
            result.add(
                "RG-001", Status.OK, f"{clean} log grubu", region,
                f"Son {cfg.log_lookback_hours} saatin örnekleminde kişisel veri deseni yok",
            )
    return result
