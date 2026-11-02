"""Dis cagrilar (RG-004): Route 53 Resolver sorgu loglarindaki alan adlari.

Istanbul LZ'de Resolver sorgu logu hic kayit dusurmedi (02.11.2026 denemesi).
DNS kaydi yoksa Flow Logs'taki AWS disi hedefler bilinen alan adlarinin
cozulmus adresleriyle ve ters DNS ile eslestirilir.

DNS sorgusu, uygulamanin bir dis servise baglanmak uzere oldugunu gosterir;
gonderilen verinin icerigini gostermez. Siniflandirma bu yuzden temkinli:
kisisel veri ya da magaza verisi gonderdigi bilinen servisler hata, digerleri
uyari, AWS API'leri ve isletim sistemi paket depolari bilgi.
"""

from __future__ import annotations

import ipaddress
import socket
from collections import defaultdict
from datetime import timedelta
from typing import Callable, Iterable

from residency_guard.aws import Context, athena_query
from residency_guard.model import CheckResult, Section, Status
from residency_guard.report import human_bytes

AWS_SUFFIXES = ("amazonaws.com", "amazonaws.com.cn", "api.aws", "aws", "amazontrust.com", "internal",
                "in-addr.arpa", "ip6.arpa")
OS_SUFFIXES = ("ubuntu.com", "canonical.com", "launchpad.net", "snapcraft.io", "snapcraftcontent.com")
CDN_SUFFIXES = ("cloudfront.net",)
# Yorum yazari, e-posta karmasi ya da magaza kullanim verisi gonderen servisler
DATA_SHARING = {
    "gravatar.com": "Gravatar: yorum yazarının e-posta karması",
    "akismet.com": "Akismet: yorum içeriği, yazar adı, e-posta ve IP",
    "pixel.wp.com": "WooCommerce Tracks: kullanım izleme",
    "stats.wp.com": "WordPress.com istatistikleri",
    "tracking.woocommerce.com": "WooCommerce kullanım izleme (mağaza verisi)",
}
KNOWN_EXTERNAL = {
    "api.wordpress.org": "WordPress çekirdek/eklenti güncelleme ve sürüm kontrolü",
    "downloads.wordpress.org": "Eklenti/tema indirme",
    "woocommerce.com": "WooCommerce pazar yeri ve öneriler",
    "public-api.wordpress.com": "WordPress.com API (Jetpack / WooCommerce servisleri)",
    "fonts.googleapis.com": "Google Fonts",
}
# Flow Logs eslestirmesinde cozulen adlar (DATA_SHARING ve KNOWN_EXTERNAL'in
# gercekte cagrilan alt alan adlari)
FORWARD_HOSTS = (
    "secure.gravatar.com", "0.gravatar.com", "rest.akismet.com", "pixel.wp.com", "stats.wp.com",
    "tracking.woocommerce.com", "api.wordpress.org", "downloads.wordpress.org", "wordpress.org",
    "woocommerce.com", "api.woocommerce.com", "public-api.wordpress.com", "fonts.googleapis.com",
)
# Ad eslesmezse adres blogu
KNOWN_NETS = {
    "192.0.64.0/18": "Automattic ağı (WordPress.com, WooCommerce, Jetpack)",
}
CLASS_LABELS = {
    "sharing": "veri paylaşan servis",
    "external": "dış servis",
    "cdn": "CDN",
    "os": "işletim sistemi",
    "aws": "AWS",
}


def _matches(name: str, suffix: str) -> bool:
    return name == suffix or name.endswith("." + suffix)


def classify(name: str) -> tuple[str, str]:
    """(sinif, aciklama); sinif: aws | os | cdn | sharing | external"""
    name = name.rstrip(".").lower()
    for domain, note in DATA_SHARING.items():
        if _matches(name, domain):
            return "sharing", note
    if any(_matches(name, s) for s in AWS_SUFFIXES):
        return "aws", "AWS API / VPC içi"
    if any(_matches(name, s) for s in OS_SUFFIXES):
        return "os", "İşletim sistemi paketleri"
    if any(_matches(name, s) for s in CDN_SUFFIXES):
        return "cdn", "CloudFront: uygulama kendi sitesini CDN üzerinden çağırıyor (loopback, wp-cron)"
    for domain, note in KNOWN_EXTERNAL.items():
        if _matches(name, domain):
            return "external", note
    return "external", "Bilinmeyen dış servis"


def check_dns(ctx: Context) -> CheckResult:
    cfg = ctx.config
    result = CheckResult("Dış çağrılar")
    if not (cfg.athena_ready and cfg.dns_logs_table):
        result.add(
            "RG-004", Status.WARN, "-", "-",
            "DNS sorgu logu ayarı yok; uygulamanın dış çağrıları ölçülemedi",
        )
        return result

    start = ctx.now - timedelta(hours=cfg.window_hours)
    sql = f"""
SELECT regexp_replace(lower(query_name), '\\.$', '') AS name, count(*) AS queries
FROM "{cfg.glue_database}"."{cfg.dns_logs_table}"
WHERE date >= '{start:%Y/%m/%d}'
  AND from_iso8601_timestamp(query_timestamp) >= from_unixtime({int(start.timestamp())})
  AND vpc_id = '{cfg.vpc_id}'
GROUP BY 1
ORDER BY queries DESC
LIMIT 5000
""".strip()
    try:
        rows = athena_query(ctx, sql)
    except Exception as exc:  # noqa: BLE001
        result.add("RG-004", Status.WARN, "-", "-", f"DNS sorgusu çalışmadı ({type(exc).__name__}); dış çağrılar ölçülemedi")
        result.gaps.append(f"DNS sorgusu: {exc}")
        return result
    if not rows:
        result.gaps.append(
            f"Son {cfg.window_hours} saatte DNS sorgu kaydı yok (kayıt kapalı ya da loglar henüz S3'e düşmedi); "
            "dış çağrılar Flow Logs hedeflerinden çıkarıldı"
        )
        _from_flows(ctx, result, start)
        return result

    by_class: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    for row in rows:
        name = row["name"] or ""
        cls, note = classify(name)
        by_class[cls].append((name, int(row["queries"] or 0), note))

    for name, count, note in by_class["sharing"]:
        result.add(
            "RG-004", Status.FAIL, name, "internet",
            f"{note}; {count} sorgu. Kişisel veri Türkiye dışındaki bir servise gidebilir",
            {"queries": count},
        )
    for cls in ("external", "cdn"):
        for name, count, note in by_class[cls]:
            result.add("RG-004", Status.WARN, name, "internet", f"{note}; {count} sorgu", {"queries": count})
    for cls, label in (("aws", "AWS API"), ("os", "işletim sistemi paket deposu")):
        if by_class[cls]:
            total = sum(c for _, c, _ in by_class[cls])
            result.add(
                "RG-004", Status.OK, f"{len(by_class[cls])} alan adı", "-",
                f"{label}: {total} sorgu (kontrol trafiği, kişisel veri taşımaz)",
            )

    result.sections.append(
        Section(
            title=f"DNS sorguları (son {cfg.window_hours} saat)",
            columns=["Alan adı", "Sınıf", "Sorgu", "Not"],
            rows=[
                [name, CLASS_LABELS[cls], count, note]
                for cls in ("sharing", "external", "cdn", "os", "aws")
                for name, count, note in sorted(by_class[cls], key=lambda r: -r[1])[:40]
            ],
            note="Bir DNS sorgusu bağlantı niyetini gösterir; gönderilen içeriği göstermez.",
        )
    )
    return result


def forward_resolve(hosts: Iterable[str]) -> dict[str, str]:
    """adres -> alan adi"""
    out: dict[str, str] = {}
    for host in hosts:
        try:
            for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
                names = out.get(info[4][0], "")
                if host not in names.split(" / "):
                    out[info[4][0]] = f"{names} / {host}" if names else host
        except OSError:
            continue
    return out


def reverse_resolve(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def match_destinations(
    rows: list[dict[str, str | None]],
    forward: dict[str, str],
    reverse: Callable[[str], str | None],
) -> list[tuple[str, int, str | None, str, int]]:
    """(adres, port, ad, eslestirme, bayt); yalnizca genel adresler"""
    totals: dict[tuple[str, int], int] = defaultdict(int)
    for row in rows:
        try:
            ip = ipaddress.ip_address(row["dstaddr"] or "")
        except ValueError:
            continue
        if ip.is_global:
            totals[(str(ip), int(row["dstport"] or 0))] += int(row["bytes"] or 0)

    out = []
    for (ip, port), size in sorted(totals.items(), key=lambda kv: -kv[1]):
        name, how = forward.get(ip), "ad çözümleme"
        if not name:
            name, how = reverse(ip), "ters DNS"
        if not name:
            net = next((n for n in KNOWN_NETS if ipaddress.ip_address(ip) in ipaddress.ip_network(n)), None)
            how = KNOWN_NETS[net] if net else "eşleşmedi"
        out.append((ip, port, name, how, size))
    return out


def _from_flows(ctx: Context, result: CheckResult, start) -> None:
    cfg = ctx.config
    if not cfg.flow_logs_table:
        result.add("RG-004", Status.WARN, "-", "-", "DNS sorgu kaydı ve Flow Logs yok; dış çağrılar ölçülemedi")
        return
    sql = f"""
SELECT dstaddr, dstport, sum(bytes) AS bytes
FROM "{cfg.glue_database}"."{cfg.flow_logs_table}"
WHERE date >= '{start:%Y/%m/%d}'
  AND start >= {int(start.timestamp())}
  AND vpc_id = '{cfg.vpc_id}'
  AND flow_direction = 'egress'
  AND action = 'ACCEPT'
  AND coalesce(pkt_dst_aws_service, '-') = '-'
GROUP BY 1, 2
ORDER BY bytes DESC
LIMIT 2000
""".strip()
    try:
        rows = athena_query(ctx, sql)
    except Exception as exc:  # noqa: BLE001
        result.add("RG-004", Status.WARN, "-", "-", f"Flow Logs sorgusu çalışmadı ({type(exc).__name__}); dış çağrılar ölçülemedi")
        return

    dests = match_destinations(rows, forward_resolve(FORWARD_HOSTS), reverse_resolve)
    if not dests:
        result.add("RG-004", Status.WARN, "-", "-", "DNS kaydı yok ve Flow Logs'ta AWS dışı genel bir hedef görünmedi")
        return

    quiet: dict[str, int] = defaultdict(int)
    table = []
    for ip, port, name, how, size in dests:
        # Ayni adresi paylasan adlar "a / b" olarak gelir; ilki siniflandirir
        cls, note = classify(name.split(" / ")[0]) if name else ("external", how)
        if name is None and how != "eşleşmedi":
            note = how
        plain = "; şifresiz HTTP" if port == 80 else ""
        label = name or "-"
        table.append([ip, port, label, CLASS_LABELS[cls], human_bytes(size), how])
        evidence = {"address": ip, "port": port, "bytes": size, "match": how}
        if cls == "sharing":
            result.add(
                "RG-004", Status.FAIL, label, "internet",
                f"{note}; {ip}:{port} adresine {human_bytes(size)} gitti{plain}. "
                "Kişisel veri Türkiye dışındaki bir servise gidebilir",
                evidence,
            )
        elif cls in ("external", "cdn"):
            target = label if name else f"{ip}:{port}"
            result.add("RG-004", Status.WARN, target, "internet", f"{note}; {human_bytes(size)} gitti{plain}", evidence)
        else:
            quiet[cls] += size
    for cls, size in quiet.items():
        result.add("RG-004", Status.OK, CLASS_LABELS[cls], "-", f"{human_bytes(size)} (kontrol trafiği, kişisel veri taşımaz)")

    result.sections.append(
        Section(
            title=f"AWS dışı hedefler, Flow Logs'tan (son {cfg.window_hours} saat)",
            columns=["Adres", "Port", "Alan adı", "Sınıf", "Bayt", "Eşleştirme"],
            rows=table[:40],
            note=(
                "DNS sorgu logu olmadığı için alan adları, bilinen servislerin bu makineden çözülen adresleriyle "
                "ve ters DNS ile eşleştirildi. CDN arkasındaki servislerin adresi bölgeye göre değişebilir; "
                "eşleşmeyen adresler elle bakılmalı."
            ),
        )
    )
