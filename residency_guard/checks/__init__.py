"""Kontroller, calisma sirasiyla. Envanter once calisir: kisisel kaynak listesini
sonrakilere (kopyalar, yedek politikasi) ctx.shared uzerinden verir."""

from __future__ import annotations

from typing import Callable

from residency_guard.aws import Context
from residency_guard.checks.compute import check_compute
from residency_guard.checks.dns import check_dns
from residency_guard.checks.inventory import check_backup_policies, check_copies, check_inventory
from residency_guard.checks.logs import check_logs
from residency_guard.checks.network import check_audit_data, check_network
from residency_guard.model import CheckResult

CHECKS: list[tuple[str, Callable[[Context], CheckResult]]] = [
    ("inventory", check_inventory),
    ("copies", check_copies),
    ("backup", check_backup_policies),
    ("logs", check_logs),
    ("compute", check_compute),
    ("network", check_network),
    ("audit", check_audit_data),
    ("dns", check_dns),
]


def run_checks(ctx: Context, skip: set[str] | None = None) -> list[CheckResult]:
    results = []
    for key, fn in CHECKS:
        if skip and key in skip:
            results.append(CheckResult(key, gaps=[f"'{key}' kontrolü --skip ile atlandı"]))
            continue
        try:
            results.append(fn(ctx))
        except Exception as exc:  # noqa: BLE001
            results.append(
                CheckResult(key, gaps=[f"'{key}' kontrolü çalışmadı: {type(exc).__name__}: {exc}"], crashed=True)
            )
    return results
