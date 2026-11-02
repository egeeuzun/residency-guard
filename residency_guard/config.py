"""Guard ayarlari. Kaynak: `terraform output -json residency_guard` (envs/istanbul-lz)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, fields
from pathlib import Path

_ID_PATTERNS = {
    "vpc_id": r"vpc-[0-9a-f]{8,17}",
    "glue_database": r"[a-z0-9_]{1,255}",
    "flow_logs_table": r"[a-z0-9_]{1,255}",
    "dns_logs_table": r"[a-z0-9_]{1,255}",
}


@dataclass
class Config:
    region: str = "eu-central-1"
    local_zone: str = "eu-central-1-ist-1a"
    local_zone_id: str | None = None
    vpc_id: str | None = None

    role_arn: str | None = None
    audit_bucket: str | None = None
    athena_workgroup: str | None = None
    glue_database: str | None = None
    flow_logs_table: str | None = None
    dns_logs_table: str | None = None
    capture_enabled: bool = False
    retention_days: int | None = None

    # data-residency etiketinin beklenen degeri
    residency_value: str = "tr"
    # Envanter ve kopya taramasi: "all" = hesapta acik tum bolgeler
    regions: list[str] | str = "all"
    # Log ornekleme bolgeleri; bos = yalnizca region
    log_regions: list[str] = field(default_factory=list)
    log_lookback_hours: int = 72
    log_max_events: int = 500
    # Akis ve DNS sorgularinin penceresi
    window_hours: int = 24

    @classmethod
    def load(cls, path: str | Path | None, **overrides: object) -> "Config":
        data: dict[str, object] = {}
        if path:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            # `terraform output -json` (tum ciktilar) da kabul: {"residency_guard": {"value": {...}}}
            if "residency_guard" in data and isinstance(data["residency_guard"], dict):
                data = data["residency_guard"].get("value", data["residency_guard"])
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"bilinmeyen ayar(lar): {', '.join(sorted(unknown))}")
        data.update({k: v for k, v in overrides.items() if v is not None})
        cfg = cls(**data)  # type: ignore[arg-type]
        cfg.validate()
        return cfg

    def validate(self) -> None:
        # Bu degerler Athena SQL'ine girer; beklenen bicim disinda bir sey kabul edilmez.
        for name, pattern in _ID_PATTERNS.items():
            value = getattr(self, name)
            if value is not None and not re.fullmatch(pattern, value):
                raise ValueError(f"{name} gecersiz: {value!r}")
        if not re.fullmatch(r"[a-z]{2}-[a-z]+-\d-[a-z]{3}-\d[a-z]", self.local_zone):
            raise ValueError(f"local_zone bir Local Zone adi degil: {self.local_zone!r}")
        if not self.local_zone.startswith(self.region + "-"):
            raise ValueError(f"{self.local_zone} {self.region} bolgesine ait degil")

    @property
    def athena_ready(self) -> bool:
        return bool(self.athena_workgroup and self.glue_database and self.vpc_id)
