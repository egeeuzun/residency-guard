"""Log satirlarinda kisisel veri deseni arar. Eslesen degerler disari verilmez, sayilir."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_TCKN = re.compile(r"(?<!\d)[1-9]\d{10}(?!\d)")


def is_valid_tckn(value: str) -> bool:
    """T.C. kimlik numarasi saglama kurali (10. ve 11. haneler)."""
    if len(value) != 11 or not value.isdigit() or value[0] == "0":
        return False
    d = [int(c) for c in value]
    d10 = ((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10
    d11 = sum(d[:10]) % 10
    return d[9] == d10 and d[10] == d11


def _public_ips(text: str) -> int:
    count = 0
    for match in _IPV4.findall(text):
        try:
            ip = ipaddress.IPv4Address(match)
        except ipaddress.AddressValueError:
            continue
        # Ozel adresler (ALB, task, VPC) kisiyi gostermez; ziyaretci IP'si geneldir.
        if ip.is_global:
            count += 1
    return count


def scan(lines: list[str]) -> Counter[str]:
    """Satirlardaki desen sayilari: ip, email, tckn ve eslesen satir sayisi (lines)."""
    hits: Counter[str] = Counter()
    for line in lines:
        ip = _public_ips(line)
        email = len(_EMAIL.findall(line))
        tckn = sum(1 for m in _TCKN.findall(line) if is_valid_tckn(m))
        if ip or email or tckn:
            hits["lines"] += 1
        hits["ip"] += ip
        hits["email"] += email
        hits["tckn"] += tckn
    return +hits


def describe(hits: Counter[str]) -> str:
    labels = {"ip": "IP", "email": "e-posta", "tckn": "TCKN"}
    parts = [f"{hits[k]} {v}" for k, v in labels.items() if hits.get(k)]
    return ", ".join(parts) if parts else "desen yok"
