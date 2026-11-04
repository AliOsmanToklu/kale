# kale

**[English](README.md) · [Türkçe](README.tr.md)**

Birçok güvenlik aracı için tek komut satırı ve tek sonuç biçimi.

kale modüler bir güvenlik araç takımıdır. Her araç bir **modül** olarak takılır: bir
**gözlemlenebilir** (dosya, alan adı, URL, IP, hash, ...) alır ve **bulgular** ile yeni
gözlemlenebilirler döndürür. Bütün modüllerin çıktısı aynı şemaya uyar; bu sayede sonuçlar
karşılaştırılabilir, saklanabilir, başka modüllere aktarılabilir ve ileride bir API ya da
arayüz tarafından sunulabilir.

Mevcut araçlar ince adaptörlerle bağlanır ve bağımsız projeler olarak kalır:

| Modül | Sarmaladığı araç | Girdi | Tür |
|---|---|---|---|
| `logs.auth` | [log-analyzer](https://github.com/AliOsmanToklu/log-analyzer): SSH / Windows oturum loglarında kaba kuvvet, hesap ele geçirme ve kullanıcı adı taraması | dosya | pasif |
| `malware.static` | [malware-static-analyzer](https://github.com/AliOsmanToklu/malware-static-analyzer): PE import ve section analizi, şüpheli string'ler, hash'ler ve sezgisel risk puanı; analiz izole bir süreçte yapılır | dosya | pasif |
| `web.scan` | [Kalkan](https://github.com/AliOsmanToklu/KALKAN): TLS, başlıklar, açıkta kalan dosyalar, portlar, eski yazılımlar, SPF/DMARC/DKIM, DNS | alan adı, URL, IP | aktif |

## Kurulum

Python 3.12+ gerekir. Sarmalanan araçlar kendi repolarından, bu reponun yanına kurulur:

```bash
git clone https://github.com/AliOsmanToklu/kale.git
git clone https://github.com/AliOsmanToklu/log-analyzer.git
git clone https://github.com/AliOsmanToklu/KALKAN.git kalkan
git clone https://github.com/AliOsmanToklu/malware-static-analyzer.git
cd kale
uv venv .venv
uv pip install -e ../log-analyzer -e ../kalkan -e ../malware-static-analyzer -e ".[dev]"
```

Aracı kurulu olmayan bir modül `kale modules` çıktısında "kullanılamaz" olarak görünür;
diğerleri çalışmaya devam eder. Araçlar bilerek paket bağımlılığı olarak tanımlanmadı:
PyPI'da yoklar ve orada sürümü sabitlenmemiş bir isim başka birinin paketine çözülebilir.

## Kullanım

```bash
kale modules                                  # modülleri listele
kale modules logs.auth                        # kabul ettiği girdi, seçenekler, varsayılanlar
kale run logs.auth /var/log/auth.log          # metin rapor
kale run logs.auth logons.csv -f json -o report.json
kale run logs.auth auth.log --set threshold=5 --set window=120
kale run web.scan example.com --scope example.com --lang tr
kale run logs.auth auth.log --fail-on high    # yüksek/acil bulgu varsa 1 ile çık (CI)
kale schema                                   # sonuç biçiminin JSON şeması
```

Hedefin türü biçiminden tahmin edilir (var olan bir yol dosyadır, `https://...` bir URL'dir
vb.); `--kind` bu tahmini geçersiz kılar.

Çıkış kodları: `0` tamamlandı, `1` bir bulgu `--fail-on` eşiğine ulaştı, `2` kullanım hatası,
`3` modül çalışamadı (nedeni raporda yazar).

### Yetki ve kapsam (scope)

Aktif modüller hedefe trafik gönderir. Sahibinin izni olmadan sistem taramak suç
olabilir (TCK 243-244). Bu yüzden aktif modüller, hedef bir kapsamda listelenmedikçe
çalışmaz:

```bash
kale run web.scan shop.example.com --scope example.com       # alt alan adları dahil
kale run web.scan 198.51.100.7 --scope 198.51.100.0/24
kale run web.scan intranet.local --scope-file scope.txt --allow-private
```

Kapsam dosyasında her satırda bir alan adı veya CIDR bulunur; `#` yorum başlatır. Özel
ve ayrılmış adresler için ayrıca `--allow-private` gerekir.

## Sonuç biçimi

Her çalıştırma bir `ModuleResult` üretir ([şema](schemas/result.v1.json)). Alanların
açıklaması ve örnek JSON için [İngilizce README](README.md#result-format)'ye bakın.

- `rule_id` sürümler arasında sabittir; bulgular takip edilebilir, bastırılabilir, karşılaştırılabilir.
- `severity`: `critical`, `high`, `medium`, `low`, `info`.
- `observables` başka modüllerin girdi olarak kullanabileceği bilgilerdir (itibar sorgusu
  için saldırgan IP, CVE sorgusu için yazılım sürümü).
- Hatalar çalıştırmayı düşürmez: `error` alanında bir kodla görünür (`invalid_input`,
  `out_of_scope`, `missing_secret`, `timeout`, `failed`).

## Modül yazmak

Modül; bir `spec` ve async bir `run` içeren bir sınıftır. Eklentinin `pyproject.toml`
dosyasında `kale.modules` entry-point grubuna kaydedilir. Eklenti yüklemek kod çalıştırmak
demek olduğundan, üçüncü taraf eklentiler yalnızca izin listesindeyse yüklenir:
`KALE_PLUGINS=intel.hash`. Girdi türü, kapsam, sırlar, seçenekler, zaman aşımı ve hata
raporlama motor tarafından yapılır. Örnek kod için [İngilizce README](README.md#writing-a-module)'ye
bakın. `tests/test_contract.py` her kayıtlı modülü kurallara karşı otomatik olarak test eder.

## Geliştirme

```bash
ruff format --check . && ruff check . && mypy && pytest --cov --cov-fail-under=90
```

Testler ağa hiç çıkmaz: Kalkan adaptörü sahte bir tarayıcıyla test edilir.

## Yol haritası

1. **Çekirdek** (bu sürüm): sözleşme, registry, motor, kapsam, CLI ve üç aracın adaptörleri:
   `logs.auth`, `malware.static`, `web.scan`.
2. **Repo ve CI**: sarmalanan araçları kale'nin yanına checkout edip sözleşme testlerini onlara
   karşı çalıştıran CI.
3. **Yeni modüller**: `intel.enrich` (IP/alan adı/URL/hash itibarı), `vuln.intel` (OSV/NVD'den
   CVE'ler, CISA KEV ve EPSS ile önceliklendirme), `surface.discover` (Certificate
   Transparency'den alt alan adları, subdomain takeover). Ardından her modülün
   gözlemlenebilirlerini bir sonrakine aktaran `kale investigate`.
4. **Arayüzler**: iş kuyruklu FastAPI servisi, HTML/PDF raporlar, web arayüzü.
5. **Derinlik**: YARA, Sigma kuralları, EVTX, SARIF ve STIX dışa aktarma, MITRE ATT&CK eşlemesi.

## Lisans

[MIT](LICENSE)
