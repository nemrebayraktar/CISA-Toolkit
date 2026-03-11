# 🛡 CISA IT Audit Toolkit — Professional Edition

**PyWebView + Flask tabanlı masaüstü IT denetim uygulaması**

CISA (Certified Information Systems Auditor) domainlerini kapsayan 30+ denetim aracı.

---

## 🚀 Kurulum (macOS)

### Yöntem 1: Çift Tıkla Aç (En Kolay)

```bash
# 1. ZIP'i çıkar
# 2. Terminal'de bir kez çalıştır (izin vermek için):
chmod +x "CISA Audit Toolkit.command"
# 3. Artık Finder'dan çift tıklayarak açabilirsin!
```

### Yöntem 2: Terminal

```bash
cd cisa-toolkit-pro
pip3 install flask pywebview
python3 app.py
```

### Yöntem 3: Sadece Tarayıcıda

```bash
python3 app.py --web
```

---

## 🖥 macOS'ta Uygulama Olarak Kullanma

### Dock'a Ekleme (Automator ile)

1. **Automator** uygulamasını aç
2. "Uygulama" (Application) seç
3. "Shell Scripti Çalıştır" (Run Shell Script) ekle
4. Şunu yapıştır:
   ```bash
   cd /path/to/cisa-toolkit-pro
   python3 app.py
   ```
5. Kaydet → İstediğin yere (örn: Applications klasörü)
6. Dock'a sürükle — artık tek tıkla açılır!

### İkon Değiştirme (Opsiyonel)
- `.icns` formatında bir ikon bul/oluştur
- Automator uygulamasına sağ tık → Get Info
- İkonu sürükle bırak

---

## 📋 Araç Listesi (30+ Fonksiyon)

### 🔐 Erişim Kontrol (6 araç)
- Kullanıcı analizi ve risk sınıflandırma
- Sudo/wheel grup üyeleri tespiti
- Parola politikası denetimi (login.defs + PAM)
- Son giriş kayıtları ve başarısız denemeler
- Kritik dosya izinleri kontrolü (SUID/SGID)
- Grup üyelik analizi

### 🌐 Ağ Güvenlik (8 araç)
- **Multi-threaded port tarayıcı** (1-65535, 500 thread, banner grabbing)
- Aktif bağlantılar ve dinleyen servisler
- Firewall durumu (UFW + iptables + ip6tables)
- DNS çözümleme kontrolü (A, MX, TXT)
- **SSL/TLS sertifika analizi** (süre, şifreleme, protokol)
- WHOIS sorgusu
- ARP tablosu
- Routing tablosu ve ağ arayüzleri

### ⚙️ Sistem Denetim (8 araç)
- Detaylı sistem bilgisi
- Güncelleme kontrolü (güvenlik yamaları)
- Çalışan ve aktif servisler
- SSH yapılandırma denetimi (7 kontrol noktası)
- Kernel güvenlik parametreleri (sysctl)
- Zamanlanmış görevler (cron + at)
- Process analizi
- Disk şifreleme kontrolü

### 📋 Log Analizi (4 araç)
- Auth/kimlik doğrulama logları + brute-force tespiti
- Sistem hata ve uyarı logları
- Ağ/firewall logları
- Kernel logları

### ⚠ Zafiyet Tarama (2 araç)
- **Nmap entegrasyonu** (6 tarama modu: basic, aggressive, vuln, full, UDP, stealth)
- OS CVE ve güvenlik güncelleme kontrolü

### ✅ Uyumluluk (16 kontrol)
- Kapsamlı CISA uyumluluk taraması
- Yüzdelik skorlama
- Otomatik risk derecelendirme

### 📄 Raporlama
- **CISA-uyumlu HTML rapor** oluşturma
- Risk matrisi (Impact × Likelihood)
- Bulgu templatelerı (BULGU-001, BULGU-002...)
- ISACA/COBIT/ISO 27001/NIST referansları
- İndirilebilir rapor dosyası
- İmza ve onay bölümü

---

## ⚠️ Önemli Notlar

- Bazı fonksiyonlar **sudo** yetkisi gerektirir
- Port taraması ve Nmap sadece yetkilendirilmiş hedeflerde kullanılmalıdır
- Nmap taraması için `nmap` kurulu olmalıdır: `brew install nmap`
- Bu araç eğitim ve iç denetim amaçlıdır
