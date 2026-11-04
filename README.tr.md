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

Yerleşik modüller doğrudan kale'nin parçasıdır:

| Modül | Ne yapar | Girdi | Tür |
|---|---|---|---|
| `intel.enrich` | GreyNoise, AbuseIPDB, URLhaus, MalwareBazaar ve VirusTotal'dan itibar bilgisi | IP, alan adı, URL, hash | pasif |

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

### Tehdit istihbaratı

`intel.enrich`, yapılandırılmış her kaynağa bir gözlemlenebiliri sorar ve her birinin ne
dediğini raporlar (kötü amaçlı, şüpheli, zararsız ya da veri yok):

```bash
kale run intel.enrich 185.10.20.30
kale run intel.enrich 468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e
kale run intel.enrich https://evil.example/payload.bin --set sources=urlhaus,virustotal
```

| Kaynak | Neye bakar | Ortam değişkeni |
|---|---|---|
| GreyNoise Community | IPv4: internet çapında tarayıcılar, bilinen servisler | `GREYNOISE_API_KEY` (isteğe bağlı) |
| AbuseIPDB | IP kötüye kullanım bildirimleri | `ABUSEIPDB_API_KEY` |
| URLhaus (abuse.ch) | zararlı yazılım dağıtan URL'ler ve onları barındıran sunucular | `ABUSECH_AUTH_KEY` |
| MalwareBazaar (abuse.ch) | hash'e göre bilinen zararlı yazılım örnekleri | `ABUSECH_AUTH_KEY` |
| VirusTotal | IP, alan adı, URL ve hash'ler için kayıtlı raporlar | `VIRUSTOTAL_API_KEY` |

Anahtarı olmayan kaynaklar atlanır ve özette listelenir; GreyNoise az sayıda sorgu için
anahtarsız da çalışır. VirusTotal'ın ücretsiz API'si ticari olmayan kullanım içindir ve
dakikada 4 isteğe izin verir; kale bu sınıra uyar.

Bir değeri sorgulamak, onu kaynağa açıklamak demektir. Bu yüzden kale özel veya ayrılmış
adresleri, iç ağ adlarını (`.local`, `.corp`, tek etiketli adlar, ...) ve kimlik bilgisi
içeren URL'leri hiçbir zaman göndermez. Dosyalar asla yüklenmez, yalnızca hash'leri
sorgulanır; URL'ler de taramaya gönderilmez. Cevaplar 24 saat önbellekte tutulur
(`--set cache_hours=0` önbelleği kapatır, `KALE_CACHE_DIR` yerini değiştirir); böylece
incelemeler ücretsiz kotaları tüketmez.

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
raporlama motor tarafından yapılır. Modülün onsuz da çalışabildiği anahtarlar `secrets`
yerine `optional_secrets` içinde tanımlanır; yalnızca ayarlanmışlarsa modüle ulaşırlar.
Örnek kod için [İngilizce README](README.md#writing-a-module)'ye
bakın. `tests/test_contract.py` her kayıtlı modülü kurallara karşı otomatik olarak test eder.

## Geliştirme

```bash
ruff format --check . && ruff check . && mypy && pytest --cov --cov-fail-under=90
```

Testler ağa hiç çıkmaz: Kalkan adaptörü sahte bir tarayıcıyla, `intel.enrich` sahte bir
HTTP katmanıyla test edilir.

## Yol haritası

1. **Çekirdek** (tamamlandı): sözleşme, registry, motor, kapsam, CLI, üç aracın adaptörleri
   (`logs.auth`, `malware.static`, `web.scan`) ve hepsini birlikte test eden CI.
2. **Yeni modüller** (sürüyor): `intel.enrich` (tamamlandı), `vuln.intel` (OSV/NVD'den
   CVE'ler, CISA KEV ve EPSS ile önceliklendirme), `surface.discover` (Certificate
   Transparency'den alt alan adları, subdomain takeover). Ardından her modülün
   gözlemlenebilirlerini bir sonrakine aktaran `kale investigate`.
3. **Arayüzler**: iş kuyruklu FastAPI servisi, HTML/PDF raporlar, web arayüzü.
4. **Derinlik**: YARA, Sigma kuralları, EVTX, SARIF ve STIX dışa aktarma, MITRE ATT&CK eşlemesi.

## Lisans

[MIT](LICENSE)
