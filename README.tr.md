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

## Servisi çalıştırmak

kale bir ekip için servis olarak da çalışabilir: bir HTTP API modül çalıştırmalarını ve
incelemeleri kuyruğa alır, ayrı worker süreçleri de bunları işler. Sonuçlar komut satırının
yazdığı JSON belgelerinin aynısıdır ([çalıştırma](schemas/result.v1.json),
[inceleme](schemas/investigation.v1.json)).

```bash
uv pip install -e ".[server]"                # FastAPI, uvicorn, SQLAlchemy, Alembic (.[dev] içinde de var)
kale db upgrade                              # veritabanını oluştur veya güncelle
kale token create --name ci --role runner    # yalnızca bir kez gösterilir: saklayın
kale serve                                   # API http://127.0.0.1:8000, belgeler /api/docs
kale worker                                  # başka bir terminalde; gerektiği kadar başlatın
```

`reader` token'ı modülleri listeleyebilir, kapsamı ve işleri okuyabilir; `runner` token'ı
ayrıca iş gönderip iptal edebilir. Token'lar yalnızca SHA-256 özetleri olarak saklanır:
`kale token list` adları ve önekleri gösterir, `kale token revoke NAME` bir sonraki istekte
geçerli olur. Token oluşturan bir uç nokta yoktur; bunun için veritabanına erişim gerekir.

| Değişken | Varsayılan | Anlamı |
|---|---|---|
| `KALE_DATABASE_URL` | `sqlite:///<veri dizini>/kale.db` | SQLAlchemy URL'si; PostgreSQL için `postgresql+psycopg://` |
| `KALE_SCOPE_FILE` | ayarlı değil | sunucu kapsamı; ayarlı değilse hiçbir aktif modül çalışmaz |
| `KALE_ALLOW_PRIVATE` | `false` | kapsam içindeki özel IP adreslerine izin ver |
| `KALE_UPLOAD_DIR` | `<veri dizini>/uploads` | yüklenen dosyaların karantinası |
| `KALE_MAX_UPLOAD_MB` | `64` | yükleme boyutu sınırı |
| `KALE_MAX_RUNS` | `100` | bir incelemenin `max_runs` değerinin üst sınırı |
| `KALE_JOB_TIMEOUT` | `3600` | bir işin çalışabileceği saniye |
| `KALE_JOB_ATTEMPTS` | `3` | worker'ı sürekli çöken bir işin başarısız sayılmadan önceki alınma sayısı |
| `KALE_HEARTBEAT_SECONDS` | `15` | worker'ın işinin yaşadığını ne sıklıkla bildirdiği |
| `KALE_STALE_SECONDS` | `120` | hangi heartbeat yaşından sonra işi başka bir worker'ın devraldığı |
| `KALE_WORKER_POLL_SECONDS` | `1` | boştaki bir worker'ın kuyruğa ne sıklıkla baktığı |

Veri dizini Windows'ta `%LOCALAPPDATA%\kale`, diğer sistemlerde `$XDG_DATA_HOME/kale`
(veya `~/.local/share/kale`) olur.

**Kapsam.** Aktif modüller yalnızca sunucu kapsamındaki hedeflere dokunur; bu kapsam
`KALE_SCOPE_FILE` ile verilen, `--scope-file` biçimindeki bir dosyadır. Bir iş `scope`
göndererek kapsamı daraltabilir, asla genişletemez: sunucu kapsamında `shop.example.com`
varken `example.com` isteyen iş reddedilir. Her worker, iş başlarken işin kapsamını kapsam
dosyasıyla yeniden kesiştirir; böylece dosyadan çıkarılan bir hedefe, değişiklikten önce
kuyruğa alınmış işler bile dokunmaz. `kale serve` dosyayı başlarken okur: hedef ekledikten
sonra yeniden başlatın. Kapsam dosyası eksik veya geçersizse iki komut da başlamaz. Özel
IP adresleri için hem sunucuda `KALE_ALLOW_PRIVATE=true` hem de işte `"allow_private": true`
gerekir.

**Yüklemeler.** Dosya alan modüller (`logs.auth`, `malware.static`) dosyayı multipart bir
istekle alır. Dosya `KALE_UPLOAD_DIR` içinde (0700 izinli bir dizin) rastgele bir adla
saklanır ve gerçekten okunan baytlara göre `KALE_MAX_UPLOAD_MB` ile sınırlanır. Asla
çalıştırılmaz, hiçbir uç nokta onu geri döndürmez ve sonuç ne olursa olsun iş bitince
silinir; yalnızca adı (gösterim için), boyutu ve SHA-256 özeti kalır.

Bir alan adı işi, bir dosya işi gönderin, ardından sonucu ve metin raporunu okuyun:

```bash
curl -s http://127.0.0.1:8000/api/v1/jobs \
  -H "Authorization: Bearer $KALE_TOKEN" -H "Content-Type: application/json" \
  -d '{"kind":"run","module":"surface.discover","target":{"kind":"domain","value":"example.com"}}'
# {"id":"0b6c3f4e-...","status":"queued"}

curl -s http://127.0.0.1:8000/api/v1/jobs \
  -H "Authorization: Bearer $KALE_TOKEN" \
  -F 'job={"kind":"run","module":"logs.auth","target":{"kind":"file"}};type=application/json' \
  -F file=@auth.log

curl -s http://127.0.0.1:8000/api/v1/jobs/0b6c3f4e-... -H "Authorization: Bearer $KALE_TOKEN"
curl -s http://127.0.0.1:8000/api/v1/jobs/0b6c3f4e-.../report -H "Authorization: Bearer $KALE_TOKEN"
```

Bir iş önce `queued`, sonra `running`, en sonunda `succeeded` veya `failed` olur; kuyruktaki
bir iş `POST /api/v1/jobs/{id}/cancel` ile iptal edilebilir. `succeeded` işin bir sonuç
ürettiği anlamına gelir: modülün kendi hatası (geçersiz bir dosya, kapsam dışı bir hedef)
komut satırında olduğu gibi sonucun içindedir. `failed` altyapının pes ettiğini gösterir:
işin süresi doldu, worker üç kez çöktü veya kapsam dosyası bozuldu. `GET /api/v1/jobs`
işleri en yeniden başlayarak listeler; sonraki sayfa için elinizdeki en eski `created_at`
değerini `before` olarak gönderin.

Gerçek kullanımdan önce bilinmesi gerekenler:

- `kale serve` `127.0.0.1` adresine bağlanır. Dışarıya açmadan önce önüne bir TLS ters
  vekil sunucusu (Caddy, nginx) koyun: token'lar bir başlıkta taşınır ve ağda şifresiz
  dolaşmamalıdır.
- Anahtarsız kullanılan servislerin (NVD, CertSpotter) hız sınırları her worker sürecinin
  içinde tutulur. Anahtar yoksa tek worker çalıştırın; yoksa iki worker birlikte sınırı
  aşabilir.
- Servis anahtarları (`VIRUSTOTAL_API_KEY`, `NVD_API_KEY`, ...) yalnızca worker'ların
  ortamında bulunur. İstekler anahtar taşıyamaz; `GET /api/v1/modules` yalnızca her birinin
  ayarlı olup olmadığını söyler.

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
(ve sahte bir DNS çözümleyiciyle) test edilir. Servis, her test için ayrı bir SQLite
dosyasında FastAPI'nin test istemcisiyle, worker da işleri tek tek çalıştırarak test edilir.

## Yol haritası

1. **Çekirdek** (tamamlandı): sözleşme, registry, motor, kapsam, CLI, üç aracın adaptörleri
   (`logs.auth`, `malware.static`, `web.scan`) ve hepsini birlikte test eden CI.
2. **Yeni modüller ve pipeline** (tamamlandı): `intel.enrich`, `vuln.intel`,
   `surface.discover` ve her modülün gözlemlenebilirlerini bir sonrakine aktaran
   `kale investigate`.
3. **Arayüzler**: veritabanı kuyruğu ve worker'larıyla API servisi (tamamlandı),
   HTML/PDF raporlar, web arayüzü, PostgreSQL'li Docker imajı.
4. **Derinlik**: YARA, Sigma kuralları, EVTX, SARIF ve STIX dışa aktarma, MITRE ATT&CK eşlemesi.

## Lisans

[MIT](LICENSE)
