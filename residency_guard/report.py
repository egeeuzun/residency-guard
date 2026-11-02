"""Markdown ve JSON rapor."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from residency_guard import __version__
from residency_guard.model import RULES, CheckResult, Finding, Status

CLAIM = (
    "Bu rapor hukuki görüş değildir ve KVKK uyumu iddia etmez. Gösterdiği şey daha dar: "
    "kişisel verinin saklandığı ve işlendiği kaynakların nerede durduğu ve bunun otomatik "
    "bir denetimle kontrol edilmesi."
)

LIMITS = [
    "Ziyaretçi trafiği CloudFront'tan geçer; edge seçimi garanti değildir. HTML cache'lenmediği "
    "için sayfa ve form verisi edge'de saklanmaz, yalnızca geçer.",
    "Log taraması örneklemdir: her log grubundan son birkaç gün içindeki sınırlı sayıda satır okunur. "
    "Desen bulunmaması kişisel veri olmadığını kanıtlamaz.",
    "DNS sorgusu bir bağlantı niyetini gösterir, gönderilen içeriği göstermez.",
    "AWS kontrol düzlemi (ECS, EC2, DLM API'leri) ve metrikler parent region'dadır; bunlar kaynak "
    "meta verisidir, müşteri verisi değildir.",
]


@dataclass
class Meta:
    label: str
    generated_at: datetime
    account_id: str
    region: str
    local_zone: str
    local_zone_id: str | None
    regions: list[str]
    window_hours: int
    log_lookback_hours: int


def _redact(text: str, account_id: str, show_account: bool) -> str:
    if show_account or not account_id:
        return text
    return text.replace(account_id, "<hesap>")


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(columns: list[str], rows: list[list[Any]]) -> list[str]:
    out = ["| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"]
    out += ["| " + " | ".join(_cell(v) for v in row) + " |" for row in rows]
    return out


def counts(results: list[CheckResult]) -> Counter[Status]:
    return Counter(f.status for r in results for f in r.findings)


def exit_code(results: list[CheckResult]) -> int:
    """0: temiz, 1: bir kontrol calismadi, 2: en az bir hata (CI bunu kirmizi sayar)."""
    if counts(results)[Status.FAIL]:
        return 2
    if any(r.crashed for r in results):
        return 1
    return 0


def render_markdown(meta: Meta, results: list[CheckResult], show_account: bool = False) -> str:
    findings = [f for r in results for f in r.findings]
    total = counts(results)
    lines: list[str] = [f"# Residency Guard raporu: {meta.label}", ""]
    lines += _table(
        ["", ""],
        [
            ["Tarih", f"{meta.generated_at:%Y-%m-%d %H:%M} UTC"],
            ["Hesap", meta.account_id],
            ["Bölge", meta.region],
            ["Local Zone", f"{meta.local_zone}" + (f" ({meta.local_zone_id})" if meta.local_zone_id else "")],
            ["Envanter taranan bölgeler", ", ".join(meta.regions)],
            ["Akış ve DNS penceresi", f"son {meta.window_hours} saat"],
            ["Log örneklemi", f"son {meta.log_lookback_hours} saat"],
            ["Araç", f"residency-guard {__version__}"],
        ],
    )
    lines += ["", f"> {CLAIM}", ""]

    verdict = (
        f"**Sonuç: {total[Status.FAIL]} ❌, {total[Status.WARN]} ⚠️, {total[Status.OK]} ✅**"
        if findings else "**Sonuç: bulgu yok**"
    )
    lines += ["## Özet", "", verdict, ""]
    per_rule: dict[str, Counter[Status]] = {rule: Counter() for rule in RULES}
    for f in findings:
        per_rule[f.rule][f.status] += 1
    lines += _table(
        ["Kural", "Kontrol", "❌", "⚠️", "✅"],
        [
            [rule, title, c[Status.FAIL] or "", c[Status.WARN] or "", c[Status.OK] or ""]
            for rule, title in RULES.items()
            for c in [per_rule[rule]]
        ],
    )

    problems = sorted(
        (f for f in findings if f.status != Status.OK),
        key=lambda f: (f.status != Status.FAIL, f.rule, f.resource),
    )
    lines += ["", "## Bulgular", ""]
    if problems:
        lines += _table(
            ["Kural", "Durum", "Kaynak", "Konum", "Açıklama"],
            [[f.rule, f.status.icon, f"`{f.resource}`", f.location, f.summary + _evidence(f)] for f in problems],
        )
    else:
        lines.append("❌ veya ⚠️ bulgu yok.")

    for r in results:
        for section in r.sections:
            lines += ["", f"## {section.title}", ""]
            if section.rows:
                lines += _table(section.columns, section.rows)
            else:
                lines.append("Kayıt yok.")
            if section.note:
                lines += ["", section.note]

    ok = [f for f in findings if f.status == Status.OK]
    if ok:
        lines += ["", "## Uygun bulunanlar", "", "<details>", f"<summary>{len(ok)} kaynak / kontrol</summary>", ""]
        lines += _table(
            ["Kural", "Kaynak", "Konum", "Açıklama"],
            [[f.rule, f"`{f.resource}`", f.location, f.summary] for f in sorted(ok, key=lambda f: (f.rule, f.resource))],
        )
        lines += ["", "</details>"]

    gaps = [g for r in results for g in r.gaps]
    lines += ["", "## Kapsam ve sınırlar", ""]
    if gaps:
        lines += ["**Bu çalıştırmada tamamlanamayanlar:**", ""] + [f"- {g}" for g in gaps] + [""]
    lines += [f"- {item}" for item in LIMITS]
    lines.append("")
    return _redact("\n".join(lines), meta.account_id, show_account)


def _evidence(f: Finding) -> str:
    nbytes = f.details.get("egress_bytes_window")
    if nbytes:
        return f"; ölçüm penceresinde bu yoldan {human_bytes(nbytes)} çıktı"
    return ""


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return str(n)


def render_json(meta: Meta, results: list[CheckResult], show_account: bool = False) -> str:
    total = counts(results)
    doc = {
        "label": meta.label,
        "generated_at": meta.generated_at.isoformat(),
        "account_id": meta.account_id,
        "region": meta.region,
        "local_zone": meta.local_zone,
        "regions": meta.regions,
        "tool_version": __version__,
        "summary": {s.value: total[s] for s in Status},
        "findings": [f.to_dict() for r in results for f in r.findings],
        "sections": [s.to_dict() for r in results for s in r.sections],
        "gaps": [g for r in results for g in r.gaps],
    }
    return _redact(json.dumps(doc, ensure_ascii=False, indent=2, default=str), meta.account_id, show_account)
