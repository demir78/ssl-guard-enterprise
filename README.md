# 🛡️ SSL Guard Enterprise

SSL Guard Enterprise, kurumların IT altyapılarındaki SSL sertifikalarının ve Kök Alan Adı (WHOIS) tescil sürelerinin takibini otomatize eden, Python ve Docker tabanlı bir SOC (Security Operations Center) aracıdır.

## 🌟 Öne Çıkan Özellikler
* **Çift Katmanlı Takip:** Subdomainlerin SSL bitiş sürelerini ve Kök Domainlerin (Ana Alan Adlarının) tescil bitiş tarihlerini (WHOIS) bağımsız olarak 7/24 denetler.
* **4 Kademeli Hibrit WHOIS Motoru:** Standart WHOIS, RDAP, OSINT API'leri ve özellikle `.tr` (Türkiye) uzantılı alan adları için **TRABIS Native Socket Bypass** desteği.
* **Akıllı SSL/SNI Doğrulaması:** WAF, Cloudflare veya Load Balancer arkasındaki sistemler için IPv4 ve Strict SNI zorlaması. İsim uyuşmazlığı ve Self-Signed teşhisi.
* **Çoklu OSINT Keşfi:** Verilen kök domain altındaki subdomainleri Google Dorking, crt.sh, HackerTarget ve AlienVault OTX üzerinden bularak otomatik envantere ekler.
* **Kademeli Alarm Sistemi:** Acil (7 Gün), Kritik (15 Gün), Uyarı (30 Gün) eşiklerine göre akıllı sınıflandırma.
* **Modern Bildirimler:** Kurumsal HTML E-Posta şablonu ve Microsoft Teams / Slack Webhook entegrasyonu.
* **Kurumsal Dışa Aktarma:** Envanterin çift sekmeli (SSL ve WHOIS) olarak tek tıkla Excel (`.xlsx`) formatında indirilmesi.
* **Güvenli Mimari:** SQLite veritabanı, PBKDF2-SHA256 (Bcrypt) şifreli oturum yönetimi ve Docker üzerinden izole çalışma.

## 🚀 Kurulum (Docker ile)

Sistemi Ubuntu/Debian veya Docker destekli herhangi bir sunucuda saniyeler içinde ayağa kaldırabilirsiniz:

```bash
git clone [https://github.com/demir78/ssl-guard-enterprise.git](https://github.com/demir78/ssl-guard-enterprise.git)
cd ssl-guard-enterprise
docker-compose up -d --build
# ssl-guard-enterprise

### 🔐 Varsayılan Giriş Bilgileri
Sistem başarıyla ayağa kalktıktan sonra tarayıcınızdan `http://SUNUCU_IP:5000` adresine gidin.

* **Kullanıcı Adı:** `admin`
* **Şifre:** `admin123`

*(⚠️ Güvenliğiniz için sisteme ilk girişinizden sonra "Ayarlar" sekmesinden yönetici şifrenizi mutlaka değiştirin).*
