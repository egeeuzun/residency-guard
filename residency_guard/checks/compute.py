"""Istek isleme (RG-007): calisan ECS task'lari hangi zone'da.

Task'lar istek islerken musteri verisi bellekte ve gecici diskte durur. Bu
hesapta ECS yalnizca magaza icin kullanildigindan bolgedeki tum cluster'lara
bakilir; Frankfurt baseline'i (Fargate) da burada gorunur.
"""

from __future__ import annotations

from collections import Counter

from residency_guard.aws import Context, paginate
from residency_guard.model import CheckResult, Status


def check_compute(ctx: Context) -> CheckResult:
    cfg = ctx.config
    result = CheckResult("İstek işleme")
    ecs = ctx.client("ecs")

    for cluster_arn in paginate(ecs, "list_clusters", "clusterArns"):
        cluster = cluster_arn.split("/")[-1]
        task_arns = list(paginate(ecs, "list_tasks", "taskArns", cluster=cluster_arn, desiredStatus="RUNNING"))
        if not task_arns:
            continue
        placements: Counter[tuple[str, str, str]] = Counter()
        for i in range(0, len(task_arns), 100):
            for task in ecs.describe_tasks(cluster=cluster_arn, tasks=task_arns[i : i + 100])["tasks"]:
                launch = task.get("capacityProviderName") or task.get("launchType", "?")
                placements[(task.get("group", "-"), task.get("availabilityZone", "?"), launch)] += 1

        for (group, az, launch), count in sorted(placements.items()):
            details = {"cluster": cluster, "tasks": count, "capacity": launch}
            resource = f"{cluster}/{group}"
            if az == cfg.local_zone:
                result.add("RG-007", Status.OK, resource, az, f"{count} task Local Zone'da ({launch})", details)
            else:
                result.add(
                    "RG-007", Status.FAIL, resource, az,
                    f"{count} task Local Zone dışında ({launch}); istekleri işlerken kişisel veriyi bellekte tutar",
                    details,
                )

    if not result.findings:
        result.gaps.append(f"{cfg.region} bölgesinde çalışan ECS task'ı yok")
    return result
