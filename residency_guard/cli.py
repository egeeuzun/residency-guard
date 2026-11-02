"""residency-guard komut satiri."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from residency_guard.aws import Context, build_session, resolve_regions
from residency_guard.checks import CHECKS, run_checks
from residency_guard.config import Config
from residency_guard.model import Status
from residency_guard.report import Meta, counts, exit_code, render_json, render_markdown


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="residency-guard",
        description="Kişisel verinin Istanbul Local Zone'da kalıp kalmadığını denetler (salt okunur).",
    )
    p.add_argument("--config", help="terraform output -json residency_guard çıktısı (JSON)")
    p.add_argument("--profile", help="AWS CLI profili")
    p.add_argument("--no-assume-role", action="store_true", help="role_arn'ı üstlenme, mevcut kimlikle çalış")
    p.add_argument("--label", default="once", help="rapor etiketi: once, sonra, son ... (dosya adına girer)")
    p.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "reports"), help="rapor dizini")
    p.add_argument("--json", action="store_true", help="markdown'ın yanına JSON da yaz")
    p.add_argument("--stdout", action="store_true", help="dosyaya yazma, markdown'ı ekrana bas")
    p.add_argument("--regions", help="virgülle ayrılmış bölgeler ya da 'all' (varsayılan: all)")
    p.add_argument("--window-hours", type=int, help="akış ve DNS penceresi (saat)")
    p.add_argument("--log-lookback-hours", type=int, help="log örnekleminin geriye bakış süresi (saat)")
    p.add_argument("--log-max-events", type=int, help="log grubu başına en çok okunacak satır")
    p.add_argument(
        "--skip", default="", help=f"atlanacak kontroller, virgülle: {', '.join(k for k, _ in CHECKS)}"
    )
    p.add_argument("--show-account", action="store_true", help="hesap numarasını raporda maskeleme")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    regions = None
    if args.regions:
        regions = "all" if args.regions == "all" else [r.strip() for r in args.regions.split(",") if r.strip()]
    try:
        config = Config.load(
            args.config,
            regions=regions,
            window_hours=args.window_hours,
            log_lookback_hours=args.log_lookback_hours,
            log_max_events=args.log_max_events,
        )
    except (OSError, ValueError) as exc:
        print(f"ayar hatası: {exc}", file=sys.stderr)
        return 1

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    unknown = skip - {k for k, _ in CHECKS}
    if unknown:
        print(f"bilinmeyen kontrol: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 1

    session, account_id = build_session(config, args.profile, assume_role=not args.no_assume_role)
    ctx = Context(session=session, config=config, account_id=account_id, regions=resolve_regions(session, config))
    print(f"hesap {account_id}, {len(ctx.regions)} bölge taranıyor...", file=sys.stderr)

    results = run_checks(ctx, skip)
    meta = Meta(
        label=args.label,
        generated_at=ctx.now,
        account_id=account_id,
        region=config.region,
        local_zone=config.local_zone,
        local_zone_id=config.local_zone_id,
        regions=ctx.regions,
        window_hours=config.window_hours,
        log_lookback_hours=config.log_lookback_hours,
    )
    markdown = render_markdown(meta, results, args.show_account)

    if args.stdout:
        print(markdown)
    else:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        stem = f"{ctx.now:%Y-%m-%d}-{args.label}"
        (out / f"{stem}.md").write_text(markdown, encoding="utf-8")
        written = [out / f"{stem}.md"]
        if args.json:
            (out / f"{stem}.json").write_text(render_json(meta, results, args.show_account), encoding="utf-8")
            written.append(out / f"{stem}.json")
        for path in written:
            print(f"yazıldı: {path}", file=sys.stderr)

    total = counts(results)
    print(
        f"{total[Status.FAIL]} ❌  {total[Status.WARN]} ⚠️  {total[Status.OK]} ✅",
        file=sys.stderr,
    )
    return exit_code(results)
