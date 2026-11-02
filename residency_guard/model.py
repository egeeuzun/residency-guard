"""Bulgu modeli ve kural listesi.

Kural kimlikleri sabittir: Faz 5'teki commit'ler (fix(RG-00X): ...) ve
onceki/sonraki raporlar bunlara atif yapar. Yeni kontrol yeni numara alir.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Status(enum.Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"

    @property
    def icon(self) -> str:
        return {Status.OK: "✅", Status.WARN: "⚠️", Status.FAIL: "❌"}[self]


RULES: dict[str, str] = {
    "RG-001": "Uygulama logları Local Zone dışında",
    "RG-002": "ECS Exec oturum logları Local Zone dışında",
    "RG-003": "Local Zone'un internet ve AWS API çıkışı (NAT) Local Zone dışında",
    "RG-004": "Uygulamanın dış alan adı çağrıları",
    "RG-005": "data-residency etiketli kaynağın konumu",
    "RG-006": "Etiketsiz kişisel veri kopyası (snapshot, recovery point)",
    "RG-007": "İstek işleme (ECS task'ları) Local Zone dışında",
    "RG-008": "Yedek politikası Local Zone dışına yazıyor",
    "RG-009": "Denetim verisinin (Flow Logs, DNS logları) konumu",
}


@dataclass
class Finding:
    rule: str
    status: Status
    resource: str
    location: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.rule not in RULES:
            raise ValueError(f"bilinmeyen kural: {self.rule}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "status": self.status.value,
            "resource": self.resource,
            "location": self.location,
            "summary": self.summary,
            "details": self.details,
        }


@dataclass
class Section:
    """Raporda bulgu tablosunun disinda gosterilen olcum tablosu (akis, DNS)."""

    title: str
    columns: list[str]
    rows: list[list[Any]]
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "columns": self.columns, "rows": self.rows, "note": self.note}


@dataclass
class CheckResult:
    name: str
    findings: list[Finding] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    # Kontrolun tamamlayamadigi kisimlar (yetki yok, veri yok). Rapor bunlari
    # "Kapsam ve sinirlar"da gosterir; sessizce gecilmez.
    gaps: list[str] = field(default_factory=list)
    # Kontrol bir hatayla yarida kaldi; sonuc "temiz" sayilamaz
    crashed: bool = False

    def add(self, *args: Any, **kwargs: Any) -> Finding:
        f = Finding(*args, **kwargs)
        self.findings.append(f)
        return f
