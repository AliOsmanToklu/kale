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
| `vuln.intel` | NVD ve OSV'den bilinen açıklar; CISA KEV ve EPSS ile önceliklendirilir | yazılım, CVE | pasif |
| `surface.discover` | Certificate Transparency kayıtlarından alt alan adları, sahipsiz CNAME'ler, subdomain takeover | alan adı | pasif |

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
kale schema --investigation                   # ... ve incelemelerin şeması
```

Hedefin türü biçiminden tahmin edilir (var olan bir yol dosyadır, `https://...` bir URL'dir
vb.); `--kind` bu tahmini geçersiz kılar.

Çıkış kodları: `0` tamamlandı, `1` bir bulgu `--fail-on` eşiğine ulaştı, `2` kullanım hatası,
`3` modül çalışamadı (nedeni raporda yazar).

### İncelemeler

`kale investigate`, hedefi kabul eden her modülü çalıştırır; ardından bu modüllerin
bulduklarını kabul eden her modülü, ve bu `--depth` adım boyunca sürer (varsayılan 2).
Bir değeri kaç modül bulmuş olursa olsun, her değer bir kez analiz edilir:

```bash
kale investigate /var/log/auth.log --depth 1          # saldırgan IP'leri -> itibar
kale investigate ornek.exe                            # hash, URL, IP -> itibar
kale investigate example.com --scope example.com      # alt alan adları -> web taraması -> CVE
kale investigate example.com --modules surface.discover,intel.enrich
kale investigate example.com --set vuln.intel.max_findings=3 -f json -o rapor.json
```

Aktif modüller yalnızca kapsam (scope) içindeki değerleri görür. Başka bir modülün bulduğu
bir değer (zararlı yazılımdaki bir komuta-kontrol adresi, CT kayıtlarındaki bir alt alan
adı gibi) sırf ortaya çıktığı için taranmaz; o çalıştırma "atlandı" olarak listelenir.
`--max-runs` (varsayılan 50) modül çalıştırma sayısını sınırlar ve rapor erken durduğunda
bunu belirtir. Metin raporu bütün bulguları en kötüden başlayarak, geldiği modül ve değerle
birlikte listeler; JSON raporu `schemas/investigation.v1.json` şemasına uyar.

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

### Zafiyetler

`vuln.intel`, bir yazılım sürümünün bilinen açıklarını ya da tek bir CVE'nin ayrıntılarını,
savunanın ele alması gereken sırayla listeler:

```bash
kale run vuln.intel nginx@1.18.0                        # Kalkan'ın tanıdığı bir ürün
kale run vuln.intel "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
kale run vuln.intel pkg:npm/lodash@4.17.20             # herhangi bir paket URL'si
kale run vuln.intel CVE-2021-44228
```

Sunucu yazılımları CPE adıyla NVD'ye sorulur (bazı ürünler iki üretici adıyla kayıtlıdır,
örneğin `f5:nginx` ve `nginx:nginx`; ikisi de sorulur). JavaScript kütüphaneleri ve paket
URL'leri, GitHub advisory'leriyle onları daha iyi kapsayan OSV'ye gider. Her açık bir
öncelik alır; bulgunun önem derecesi budur:

| Öncelik | Ne zaman |
|---|---|
| critical | CISA'nın Known Exploited Vulnerabilities kataloğunda: gerçek saldırılarda kullanılıyor |
| high | EPSS %10 veya üstü (30 gün içinde sömürülmesi olası) ya da CVSS 9 veya üstü |
| medium | CVSS 7 veya üstü |
| low | geri kalan her şey |

CVSS bir saldırının ne kadar kötü olacağını söyler, ne kadar olası olduğunu değil; bu
yüzden CVSS 9.8 bir açık tek başına kritik sayılmaz. NVD anahtarsız da çalışır ama 30
saniyede yalnızca 5 isteğe izin verir ve bağlantıları sık sık keser; kale istekleri aralıklı
gönderir ve yeniden dener. `NVD_API_KEY` bu sınırı on katına çıkarır. Linux dağıtımları
güvenlik düzeltmelerini sürüm numarasını değiştirmeden geri taşıyabilir; bir eşleşmeye göre
harekete geçmeden önce dağıtımın paketini kontrol edin.

### Saldırı yüzeyi

`surface.discover`, bir alan adının hostlarını Certificate Transparency kayıtlarından
(crt.sh ve CertSpotter) çıkarır ve her adı DNS'te kontrol eder. Hostların kendisine hiçbir
istek gönderilmez; bu yüzden kapsam (scope) olmadan çalışır:

```bash
kale run surface.discover example.com
kale run surface.discover example.com --set sources=certspotter --set max_names=100
```

| Bulgu | Önem derecesi |
|---|---|
| olası subdomain takeover: herkesin sahiplenebildiği bir serviste (Azure, AWS Elastic Beanstalk) var olmayan bir ada işaret eden CNAME | high |
| sahipsiz (dangling) CNAME: aynı durum başka bir serviste | medium |
| özel IP adreslerine işaret eden genel adlar | low |
| herkese açık sertifikalarda listelenen geliştirme ve yönetim hostları (`dev.`, `staging.`, `admin.`, `jenkins.`, ...) | low |

Takeover yalnızca DNS ile tespit edilir (CNAME hedefi NXDOMAIN döndürür). S3 veya GitHub
Pages gibi servisler ancak hosta HTTP isteği atılarak doğrulanabilir; bu modülü aktif yapardı,
bu yüzden en fazla sahipsiz CNAME olarak raporlanırlar. crt.sh eksiksizdir ama yavaştır
(orta büyüklükte bir alan adı için bir dakika); CertSpotter hızlıdır ama anahtarsız saatte
yaklaşık on isteğe izin verir (`CERTSPOTTER_API_KEY`), bu yüzden yalnızca ilk sayfaları
okunur. Çözümlenen hostlar ve genel IP adresleri diğer modüller için gözlemlenebilir olur.

## Sonuç biçimi

Her çalıştırma bir `ModuleResult` üretir ([şema](schemas/result.v1.json)). Alanların
açıklaması ve örnek JSON için [İngilizce README](README.md#result-format)'ye bakın.

- `rule_id` sürümler arasında sabittir; bulgular takip edilebilir, bastırılabilir, karşılaştırılabilir.
- `severity`: `critical`, `high`, `medium`, `low`, `info`. Bulgular en kötüden başlar;
  aynı önem derecesinde, modülün belirlediği sırada kalır.
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

Testler ağa hiç çıkmaz: Kalkan adaptörü sahte bir tarayıcıyla, `intel.enrich`,
`vuln.intel` ve `surface.discover` gerçek servisleri taklit eden sahte bir HTTP katmanıyla
(ve sahte bir DNS çözümleyiciyle) test edilir.

## Yol haritası

1. **Çekirdek** (tamamlandı): sözleşme, registry, motor, kapsam, CLI, üç aracın adaptörleri
   (`logs.auth`, `malware.static`, `web.scan`) ve hepsini birlikte test eden CI.
2. **Yeni modüller ve pipeline** (tamamlandı): `intel.enrich`, `vuln.intel`,
   `surface.discover` ve her modülün gözlemlenebilirlerini bir sonrakine aktaran
   `kale investigate`.
3. **Arayüzler**: iş kuyruklu FastAPI servisi, HTML/PDF raporlar, web arayüzü.
4. **Derinlik**: YARA, Sigma kuralları, EVTX, SARIF ve STIX dışa aktarma, MITRE ATT&CK eşlemesi.

## Lisans

[MIT](LICENSE)
