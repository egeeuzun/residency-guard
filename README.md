# Residency Guard

"Kişisel veri Türkiye'de kalıyor" iddiasını kanıtlayan ya da çürüten salt okunur
denetim aracı. Hesabı tarar, kişisel veri taşıyan ya da taşıyabilecek her şeyin
nerede durduğuna bakar ve `reports/<tarih>-<etiket>.md` olarak ✅ / ⚠️ / ❌
raporu yazar.

> Hukuki görüş değildir; KVKK uyumu iddia etmez. İddia daha dar: kişisel verinin
> saklandığı ve işlendiği kaynaklar Türkiye'de ve bunu otomatik bir denetim
> kontrol ediyor.

## Kontroller

| Kural | Ne bakar | Nasıl |
| --- | --- | --- |
| RG-001 | Uygulama logları Local Zone dışında | Tüm CloudWatch log grupları: `data-class=personal` etiketi ya da örnek satırlarda IP / e-posta / TCKN deseni |
| RG-002 | ECS Exec oturum logları | Cluster'ın `executeCommandConfiguration`'ının yazdığı log grubu |
| RG-003 | LZ'nin internet ve AWS API çıkışı | LZ subnet'lerinin route table'ı → NAT → NAT'ın subnet'i ve zone'u. Flow Logs varsa o yoldan çıkan bayt |
| RG-004 | Uygulamanın dış çağrıları | Route 53 Resolver sorgu logları (Athena): AWS, OS paket deposu, CDN, dış servis, veri paylaşan servis |
| RG-005 | `data-residency=tr` etiketli kaynakların konumu | Tüm bölgelerde etiket envanteri; her kaynağın AZ / Local Zone / bölgesi |
| RG-006 | Etiketsiz kopyalar | EBS snapshot'ları (disk, şifreleme anahtarı ve açıklama üzerinden soy ağacı), RDS snapshot'ları, AWS Backup recovery point'leri |
| RG-007 | İstek işleme | Çalışan ECS task'larının zone'u (Frankfurt baseline'ındaki Fargate task'ları dahil) |
| RG-008 | Yedek politikası | Kişisel diskleri hedefleyen DLM politikalarının `Location`'ı ve bölgeler arası kopyası |
| RG-009 | Denetim verisinin konumu | Flow Logs ve DNS sorgu loglarının hedefi ve saklama süresi (bunlar da IP içerir) |

Durumlar: ❌ kişisel veri Local Zone dışında; ⚠️ belirsiz ya da elle bakılmalı;
✅ uygun. Yalnızca `eu-central-1-ist-1a` "Türkiye'de" sayılır. Kural numaraları
sabittir; bir bulguyu düzelten değişiklik `fix(RG-00X): …` diye ona atıf yapabilir.

Log taramasında eşleşen değerler rapora yazılmaz, yalnızca sayılır. Hesap
numarası raporda `<hesap>` olarak maskelenir (`--show-account` ile açılır).

## AWS tarafı

AWS kaynakları altyapı reposunda
(`../woocommerce-istanbul-local-zone`) durur: `envs/istanbul-lz`,
`modules/residency-audit` ile şunları kurar:

- **Salt okunur rol** (`<ad>-residency-guard`): envanter, log örneklemi ve Athena
  sorgusu. Yazabildiği tek yer kendi Athena sonuç klasörü.
- **Denetim bucket'ı** (Frankfurt), içindeki her şey `residency_log_retention_days`
  (varsayılan 3) gün sonra silinir.
- **Athena workgroup'u ve Glue tabloları** (`flow_logs`, `dns_logs`), partition
  projection ile; ücretsiz.
- **Ölçüm penceresi** (`residency_capture_enabled = true`): LZ VPC'sinin Flow
  Logs'u (Parquet, saatlik) ve Route 53 Resolver DNS sorgu logları. İkisi de IP
  içerir; yalnızca denetim sırasında açın.

## Çalıştırma

```bash
cd residency-guard
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'

# 1. Denetim penceresini aç (envs/istanbul-lz/terraform.tfvars)
#    residency_capture_enabled = true
#    db_snapshot_time_utc      = "12:30"   # apply'dan ~1 saat sonrası, UTC
#    Snapshot saati çekilmezse ilk DLM snapshot'ı gece 00:00 UTC'de alınır;
#    RG-006 ve RG-008'in LZ tarafı için onu beklemek gerekir.
cd ../woocommerce-istanbul-local-zone/envs/istanbul-lz && terraform apply

# 2. Trafik üret: k6 senaryoları, birkaç sipariş, bir ECS Exec oturumu.
#    Flow Logs S3'e ~10 dakikada, DNS logları birkaç dakikada düşer.

# 3. Ayarları al ve denetle
terraform output -json residency_guard > ../../../residency-guard/guard.json
cd ../../../residency-guard
.venv/bin/residency-guard --config guard.json --label once --json

# 4. Pencereyi kapat: residency_capture_enabled = false, db_snapshot_time_utc'yi sil, terraform apply
```

Çıkış kodu: `0` temiz, `1` bir kontrol çalışamadı, `2` en az bir ❌. CI'da ya da
zamanlanmış bir işte denetimi düşürmek için bu kullanılabilir.

Sık kullanılan seçenekler:

| Seçenek | Ne yapar |
| --- | --- |
| `--label sonra` | Raporun etiketi; düzeltmelerden sonraki çalıştırma için: `reports/<tarih>-sonra.md` |
| `--regions eu-central-1,us-east-1` | Envanteri bu bölgelerle sınırla (varsayılan: hesapta açık tüm bölgeler) |
| `--window-hours 6` | Akış ve DNS sorgularının penceresi |
| `--skip dns,network` | Kontrol atla: `inventory, copies, backup, logs, compute, network, audit, dns` |
| `--no-assume-role` | Rolü üstlenme, mevcut kimlikle çalış (rol henüz kurulmadıysa) |
| `--stdout` | Dosya yazma, raporu ekrana bas |

`guard.json` olmadan da çalışır; o zaman yalnızca envanter, kopyalar, loglar ve
ECS kontrolleri anlamlıdır (VPC ve Athena bilgisi yok).

## Testler

```bash
.venv/bin/python -m pytest
```

Testler AWS'ye bağlanmaz. `tests/test_scenario.py` naif LZ sürümünü ve ayaktaki
Frankfurt baseline'ını sahte istemcilerle kurar ve akış dokümanındaki beklenen
bulguları arar. `tests/test_api_shapes.py`, sahte istemcilere yapılan her
çağrının işlem ve parametre adını botocore'un gerçek API modeline karşı kontrol
eder.

## Sınırlar

- Log taraması örneklemdir; desen bulunmaması kişisel veri olmadığını kanıtlamaz.
- DNS sorgusu bağlantı niyetini gösterir, gönderilen içeriği göstermez.
- İstanbul LZ'de Route 53 Resolver sorgu logu kayıt düşürmedi (02.11.2026). DNS kaydı
  yoksa RG-004, Flow Logs'taki AWS dışı hedefleri bilinen alan adlarının çözülmüş
  adresleri ve ters DNS ile eşleştirir; CDN arkasındaki adresler eşleşmeyebilir.
- CloudFront trafiği edge'den geçer; edge seçimi garanti değildir. HTML
  cache'lenmediği için sayfa ve form verisi edge'de saklanmaz.
- AWS kontrol düzlemi ve metrikler parent region'dadır; bunlar meta veridir.
