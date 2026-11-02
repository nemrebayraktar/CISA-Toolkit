#!/usr/bin/env python3
"""
CISA IT Audit Toolkit
CISA sınavına hazırlanırken IT / BS denetimi pratiği için yazdığım
Flask tabanlı yerel denetim aracı. ISACA ile bir bağlantısı yoktur.

Kullanım:
  python3 app.py          -> PyWebView penceresi (kuruluysa)
  python3 app.py --web    -> tarayıcıda aç
  python3 app.py --port 8000

Eğitim ve iç denetim amaçlıdır; yalnızca kendi sistemlerinizde
veya yazılı izin aldığınız hedeflerde kullanın.
"""

import threading, socket, subprocess, platform, os, re, json, csv, io
import datetime, ssl, struct, time, ipaddress, hashlib, html
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, jsonify, Response, send_file
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
IS_LINUX = platform.system() == "Linux"
IS_MAC = platform.system() == "Darwin"

# Uygulama komut çalıştırdığı için sadece bu bilgisayardan erişilebilsin.
# Host kontrolü DNS rebinding'e, özel başlık kontrolü de başka bir sitenin
# arka planda POST isteği atmasına karşı.
@app.before_request
def sadece_yerel():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"error": "Sadece yerel erişim"}), 403
    host = (request.host or "").rsplit(":", 1)[0].strip("[]")
    if host not in ("127.0.0.1", "localhost", "::1"):
        return jsonify({"error": "Geçersiz host"}), 403
    if request.method == "POST" and request.headers.get("X-Requested-With") != "cisa-toolkit":
        return jsonify({"error": "Geçersiz istek"}), 403

def gecerli_hedef(t):
    # komutlara argüman olarak gidiyor; '-' ile başlayan değerler
    # (ör. nmap -oN...) seçenek gibi yorumlanmasın
    return isinstance(t, str) and 0 < len(t) <= 253 and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.\-]*', t) is not None

e = lambda v: html.escape(str(v))

# ════════════════════════════════════════════════════════════
#  YARDIMCI FONKSİYONLAR
# ════════════════════════════════════════════════════════════

def run_cmd(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or r.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

def severity_score(level):
    return {"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1}.get(level, 0)

# ════════════════════════════════════════════════════════════
#  SAYFA ROUTE
# ════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")

# ════════════════════════════════════════════════════════════
#  1. ERİŞİM KONTROL DENETİMİ
# ════════════════════════════════════════════════════════════

@app.route("/api/access/users")
def api_access_users():
    users = []
    try:
        for line in open("/etc/passwd"):
            p = line.strip().split(":")
            if len(p) >= 7:
                uid = int(p[2])
                shell = p[6]
                utype = "root" if uid == 0 else "system" if uid < 1000 else "normal"
                can_login = shell not in ["/usr/sbin/nologin","/bin/false","/sbin/nologin"]
                users.append({"username":p[0],"uid":uid,"gid":int(p[3]),
                              "home":p[5],"shell":shell,"type":utype,"login_capable":can_login})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    risk_users = [u for u in users if u["login_capable"] and u["type"]!="system"]
    return jsonify({"total":len(users),"login_capable":len([u for u in users if u["login_capable"]]),
                     "root_count":len([u for u in users if u["type"]=="root"]),
                     "risk_level":"HIGH" if len(risk_users)>5 else "MEDIUM" if len(risk_users)>2 else "LOW",
                     "users":users})

@app.route("/api/access/sudo")
def api_access_sudo():
    out = run_cmd("getent group sudo 2>/dev/null || getent group wheel 2>/dev/null")
    sudoers = run_cmd("cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | grep -v '^Defaults'")
    members = []
    if out:
        parts = out.split(":")
        if len(parts)>=4 and parts[3]:
            members = [m.strip() for m in parts[3].split(",") if m.strip()]
    return jsonify({"sudo_users":members,"count":len(members),"sudoers_config":sudoers,
                     "risk_level":"HIGH" if len(members)>3 else "MEDIUM" if len(members)>1 else "LOW"})

@app.route("/api/access/password-policy")
def api_access_pwd():
    defs = {}
    try:
        for line in open("/etc/login.defs"):
            l = line.strip()
            if l and not l.startswith("#"):
                p = l.split()
                if len(p)>=2: defs[p[0]] = p[1]
    except: pass
    pam = run_cmd("cat /etc/pam.d/common-password 2>/dev/null || echo 'N/A'")
    findings = []
    mx = int(defs.get("PASS_MAX_DAYS","99999"))
    mn = int(defs.get("PASS_MIN_DAYS","0"))
    ml = int(defs.get("PASS_MIN_LEN","0"))
    wa = int(defs.get("PASS_WARN_AGE","0"))
    if mx > 90: findings.append({"severity":"HIGH","finding":"Parola süresi çok uzun","detail":f"{mx} gün (önerilen: ≤90)","recommendation":"PASS_MAX_DAYS değerini 90 veya altına ayarlayın"})
    if mn < 1: findings.append({"severity":"MEDIUM","finding":"Minimum parola yaşı yok","detail":"Kullanıcılar parolayı hemen değiştirebilir","recommendation":"PASS_MIN_DAYS değerini en az 1 yapın"})
    if ml < 12: findings.append({"severity":"HIGH","finding":"Minimum parola uzunluğu yetersiz","detail":f"Mevcut: {ml} karakter","recommendation":"PASS_MIN_LEN değerini en az 12 yapın"})
    if wa < 7: findings.append({"severity":"LOW","finding":"Parola uyarı süresi kısa","detail":f"{wa} gün","recommendation":"PASS_WARN_AGE değerini 14 yapın"})
    if "pam_pwquality" not in pam and "pam_cracklib" not in pam:
        findings.append({"severity":"HIGH","finding":"Parola karmaşıklık modülü yok","detail":"pam_pwquality veya pam_cracklib yüklü değil","recommendation":"libpam-pwquality paketini kurun"})
    if not findings: findings.append({"severity":"INFO","finding":"Parola politikası uygun","detail":"Kontrol edilen tüm parametreler standartlara uygun","recommendation":"—"})
    risk = "HIGH" if any(f["severity"]=="HIGH" for f in findings) else "MEDIUM" if any(f["severity"]=="MEDIUM" for f in findings) else "LOW"
    return jsonify({"login_defs":defs,"pam_config":pam[:800],"findings":findings,"risk_level":risk})

@app.route("/api/access/logins")
def api_access_logins():
    last = run_cmd("last -n 25 2>/dev/null || echo 'N/A'")
    failed = run_cmd("lastb -n 15 2>/dev/null || echo 'Yetki gerekli (sudo ile çalıştırın)'")
    who = run_cmd("who 2>/dev/null")
    return jsonify({"last_logins":last,"failed_logins":failed,"current_sessions":who,
                     "risk_level":"HIGH" if failed.lower().count("failed")>5 else "LOW"})

@app.route("/api/access/file-permissions")
def api_access_fileperm():
    checks = []
    sensitive = [("/etc/passwd","644"),("/etc/shadow","640"),("/etc/group","644"),
                 ("/etc/gshadow","640"),("/etc/ssh/sshd_config","600")]
    for fpath, expected in sensitive:
        actual = run_cmd(f"stat -c '%a' {fpath} 2>/dev/null")
        ok = actual == expected if actual and "[" not in actual else None
        checks.append({"file":fpath,"expected":expected,"actual":actual or "N/A",
                       "status":"PASS" if ok else "FAIL" if ok is False else "UNKNOWN"})
    suid = run_cmd("find / -perm -4000 -type f 2>/dev/null | head -20")
    sgid = run_cmd("find / -perm -2000 -type f 2>/dev/null | head -20")
    world_w = run_cmd("find /etc -perm -002 -type f 2>/dev/null | head -10")
    fails = len([c for c in checks if c["status"]=="FAIL"])
    return jsonify({"permission_checks":checks,"suid_files":suid,"sgid_files":sgid,
                     "world_writable":world_w,
                     "risk_level":"CRITICAL" if fails>2 else "HIGH" if fails>0 else "LOW"})

@app.route("/api/access/groups")
def api_access_groups():
    groups = []
    try:
        for line in open("/etc/group"):
            p = line.strip().split(":")
            if len(p)>=4:
                members = [m for m in p[3].split(",") if m]
                if members:
                    groups.append({"name":p[0],"gid":int(p[2]),"members":members})
    except: pass
    return jsonify({"groups":groups,"total":len(groups),"risk_level":"INFO"})

# ════════════════════════════════════════════════════════════
#  2. AĞ GÜVENLİK TARAYICI (Multi-threaded)
# ════════════════════════════════════════════════════════════

def scan_port(target, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        if result == 0:
            banner = ""
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(256).decode("utf-8", errors="ignore").strip()[:100]
            except: pass
            try: service = socket.getservbyport(port)
            except: service = "unknown"
            s.close()
            return {"port":port,"service":service,"state":"open","banner":banner}
        s.close()
    except: pass
    return None

@app.route("/api/network/port-scan", methods=["POST"])
def api_network_portscan():
    d = request.json or {}
    target = d.get("target","127.0.0.1")
    port_range = d.get("port_range","1-1024")
    try:
        threads = max(1, min(int(d.get("threads", 200)), 500))
        timeout = min(max(float(d.get("timeout", 0.5)), 0.1), 5.0)
    except (TypeError, ValueError):
        return jsonify({"error":"Geçersiz thread / timeout değeri"}), 400
    scan_type = d.get("scan_type", "tcp")

    if not gecerli_hedef(target):
        return jsonify({"error":"Geçersiz hedef"}), 400

    try:
        parts = port_range.split("-")
        start_p, end_p = int(parts[0]), int(parts[1]) if len(parts)>1 else int(parts[0])
        start_p = max(1, start_p)
        end_p = min(65535, end_p)
        if start_p > end_p: start_p, end_p = end_p, start_p
    except:
        start_p, end_p = 1, 1024

    # Resolve hostname
    try:
        resolved_ip = socket.gethostbyname(target)
    except:
        return jsonify({"error":f"Hostname çözümlenemedi: {target}"}), 400

    open_ports = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, resolved_ip, p, timeout): p
                   for p in range(start_p, end_p+1)}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    elapsed = round(time.time() - start_time, 2)
    open_ports.sort(key=lambda x: x["port"])

    # Well-known risky ports
    risky = {21:"FTP",23:"Telnet",445:"SMB",3389:"RDP",5900:"VNC",6379:"Redis",
             27017:"MongoDB",3306:"MySQL-open",5432:"PostgreSQL-open"}
    risky_found = [p for p in open_ports if p["port"] in risky]

    risk = "CRITICAL" if len(risky_found)>3 else "HIGH" if len(risky_found)>0 or len(open_ports)>20 else "MEDIUM" if len(open_ports)>10 else "LOW"

    return jsonify({"target":target,"resolved_ip":resolved_ip,"scanned_range":f"{start_p}-{end_p}",
                     "total_scanned":end_p-start_p+1,"open_ports":open_ports,"total_open":len(open_ports),
                     "risky_ports":risky_found,"scan_time":f"{elapsed}s","threads_used":threads,
                     "risk_level":risk})

@app.route("/api/network/connections")
def api_network_connections():
    ss = run_cmd("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null")
    established = run_cmd("ss -tnp state established 2>/dev/null | tail -n +2")
    est_count = len([l for l in established.split("\n") if l.strip()])
    listen_count = ss.count("LISTEN")
    return jsonify({"listening":ss,"established":established,"listen_count":listen_count,
                     "established_count":est_count,
                     "risk_level":"HIGH" if listen_count>20 or est_count>50 else "MEDIUM" if listen_count>10 else "LOW"})

@app.route("/api/network/firewall")
def api_network_firewall():
    ufw = run_cmd("ufw status verbose 2>/dev/null")
    iptables = run_cmd("iptables -L -n -v 2>/dev/null || echo 'Yetki gerekli'")
    ip6 = run_cmd("ip6tables -L -n 2>/dev/null | head -20")
    fw_active = "active" in ufw.lower() if ufw else False
    rules_count = iptables.count("\n") if iptables else 0
    return jsonify({"ufw_status":ufw,"iptables":iptables[:3000],"ip6tables":ip6[:1000],
                     "firewall_active":fw_active,"rules_count":rules_count,
                     "risk_level":"CRITICAL" if not fw_active else "LOW"})

@app.route("/api/network/dns", methods=["POST"])
def api_network_dns():
    d = request.json or {}
    domain = d.get("domain","google.com")
    if not gecerli_hedef(domain):
        return jsonify({"error":"Geçersiz domain"}), 400
    ns = run_cmd(f"nslookup {domain} 2>/dev/null")
    dig = run_cmd(f"dig {domain} +short 2>/dev/null")
    mx = run_cmd(f"dig {domain} MX +short 2>/dev/null")
    txt = run_cmd(f"dig {domain} TXT +short 2>/dev/null")
    return jsonify({"domain":domain,"nslookup":ns,"a_records":dig,"mx_records":mx,"txt_records":txt,
                     "resolves":bool(dig and "NXDOMAIN" not in dig)})

@app.route("/api/network/ssl-check", methods=["POST"])
def api_network_ssl():
    d = request.json or {}
    host = d.get("host","google.com")
    port = int(d.get("port", 443))
    if not gecerli_hedef(host):
        return jsonify({"error":"Geçersiz host"}), 400
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, port))
            cert = s.getpeercert()
            cipher = s.cipher()
            proto = s.version()
        issuer = dict(x[0] for x in cert.get("issuer",[]))
        subject = dict(x[0] for x in cert.get("subject",[]))
        expires = cert.get("notAfter","")
        exp_date = datetime.datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z") if expires else None
        days_left = (exp_date - datetime.datetime.utcnow()).days if exp_date else -1
        san = [e[1] for e in cert.get("subjectAltName",[])]
        findings = []
        if days_left < 0: findings.append({"severity":"CRITICAL","message":"Sertifika süresi dolmuş!"})
        elif days_left < 30: findings.append({"severity":"HIGH","message":f"Sertifika {days_left} gün içinde dolacak"})
        if proto in ["TLSv1","TLSv1.1"]: findings.append({"severity":"HIGH","message":f"Eski TLS versiyonu: {proto}"})
        if cipher and cipher[2] < 128: findings.append({"severity":"HIGH","message":f"Zayıf şifreleme: {cipher[2]}-bit"})
        risk = "CRITICAL" if any(f["severity"]=="CRITICAL" for f in findings) else "HIGH" if any(f["severity"]=="HIGH" for f in findings) else "LOW"
        return jsonify({"host":host,"port":port,"subject":subject.get("commonName",""),
                         "issuer":issuer.get("organizationName",""),"protocol":proto,
                         "cipher":cipher[0] if cipher else "","key_bits":cipher[2] if cipher else 0,
                         "expires":expires,"days_remaining":days_left,"san":san,
                         "findings":findings,"risk_level":risk})
    except Exception as e:
        return jsonify({"host":host,"error":str(e),"risk_level":"HIGH"})

@app.route("/api/network/whois", methods=["POST"])
def api_network_whois():
    d = request.json or {}
    target = d.get("target","google.com")
    if not gecerli_hedef(target):
        return jsonify({"error":"Geçersiz hedef"}), 400
    out = run_cmd(f"whois {target} 2>/dev/null", timeout=10)
    return jsonify({"target":target,"whois_data":out[:5000],"risk_level":"INFO"})

@app.route("/api/network/arp")
def api_network_arp():
    arp = run_cmd("arp -a 2>/dev/null || ip neigh show 2>/dev/null")
    return jsonify({"arp_table":arp,"risk_level":"INFO"})

@app.route("/api/network/routes")
def api_network_routes():
    routes = run_cmd("ip route show 2>/dev/null || netstat -rn 2>/dev/null")
    ifaces = run_cmd("ip addr show 2>/dev/null || ifconfig 2>/dev/null")
    return jsonify({"routing_table":routes,"interfaces":ifaces,"risk_level":"INFO"})

# ════════════════════════════════════════════════════════════
#  3. SİSTEM YAPILANDIRMA DENETİMİ
# ════════════════════════════════════════════════════════════

@app.route("/api/system/info")
def api_system_info():
    return jsonify({
        "os":platform.system(),"release":platform.release(),"version":platform.version(),
        "machine":platform.machine(),"hostname":socket.gethostname(),
        "kernel":run_cmd("uname -r"),
        "uptime":run_cmd("uptime -p 2>/dev/null || uptime"),
        "cpu":run_cmd("sysctl -n machdep.cpu.brand_string 2>/dev/null || grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2"),
        "memory":run_cmd("free -h 2>/dev/null || vm_stat 2>/dev/null"),
        "disk":run_cmd("df -h 2>/dev/null"),
        "load":run_cmd("cat /proc/loadavg 2>/dev/null || sysctl -n vm.loadavg 2>/dev/null"),
        "risk_level":"INFO"
    })

@app.route("/api/system/updates")
def api_system_updates():
    os_t = platform.system()
    if os_t == "Darwin":
        updates = run_cmd("softwareupdate -l 2>&1", timeout=30)
        pkg = run_cmd("brew outdated 2>/dev/null || echo 'Homebrew yok'")
    else:
        updates = run_cmd("apt list --upgradable 2>/dev/null", timeout=30)
        pkg = run_cmd("dpkg -l | grep -c '^ii' 2>/dev/null")
    sec = run_cmd("grep -c security /var/log/dpkg.log 2>/dev/null || echo '0'")
    pending = updates.count("upgradable") if updates else 0
    return jsonify({"os_updates":updates[:3000],"package_info":pkg,"security_updates":sec,
                     "pending_count":pending,
                     "risk_level":"CRITICAL" if pending>20 else "HIGH" if pending>5 else "MEDIUM" if pending>0 else "LOW"})

@app.route("/api/system/services")
def api_system_services():
    os_t = platform.system()
    if os_t == "Darwin":
        svc = run_cmd("launchctl list 2>/dev/null | head -60")
    else:
        svc = run_cmd("systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -60")
    enabled = run_cmd("systemctl list-unit-files --state=enabled --no-pager 2>/dev/null | head -40")
    return jsonify({"running_services":svc,"enabled_services":enabled,"risk_level":"INFO"})

@app.route("/api/system/cron")
def api_system_cron():
    user_c = run_cmd("crontab -l 2>/dev/null || echo 'Cron yok'")
    sys_c = run_cmd("ls -la /etc/cron.* 2>/dev/null")
    at_jobs = run_cmd("atq 2>/dev/null || echo 'at komutu yok'")
    return jsonify({"user_crontab":user_c,"system_cron":sys_c,"at_jobs":at_jobs,
                     "risk_level":"MEDIUM" if "no crontab" not in user_c.lower() else "LOW"})

@app.route("/api/system/ssh")
def api_system_ssh():
    cfg = run_cmd("cat /etc/ssh/sshd_config 2>/dev/null || echo 'SSH config yok'")
    findings = []
    if cfg and "SSH config yok" not in cfg:
        checks = [
            ("PermitRootLogin yes","CRITICAL","Root SSH girişi açık","PermitRootLogin no yapın"),
            ("PasswordAuthentication yes","HIGH","Parola ile SSH aktif","Key-based auth kullanın"),
            ("PermitEmptyPasswords yes","CRITICAL","Boş parola ile giriş açık","PermitEmptyPasswords no yapın"),
            ("X11Forwarding yes","MEDIUM","X11 forwarding açık","Gerekmiyorsa kapatın"),
        ]
        for pattern, sev, finding, rec in checks:
            if pattern in cfg:
                findings.append({"severity":sev,"finding":finding,"recommendation":rec})
        if "Port 22" in cfg or not re.search(r"^Port\s", cfg, re.M):
            findings.append({"severity":"MEDIUM","finding":"SSH varsayılan port 22","recommendation":"Farklı bir port kullanın"})
        if "MaxAuthTries" not in cfg:
            findings.append({"severity":"MEDIUM","finding":"MaxAuthTries ayarsız","recommendation":"MaxAuthTries 3 yapın"})
        if "LoginGraceTime" not in cfg:
            findings.append({"severity":"LOW","finding":"LoginGraceTime ayarsız","recommendation":"LoginGraceTime 60 yapın"})
    if not findings:
        findings.append({"severity":"INFO","finding":"SSH yapılandırması uygun","recommendation":"—"})
    risk = "CRITICAL" if any(f["severity"]=="CRITICAL" for f in findings) else "HIGH" if any(f["severity"]=="HIGH" for f in findings) else "LOW"
    return jsonify({"config":cfg[:4000],"findings":findings,"risk_level":risk})

@app.route("/api/system/kernel-params")
def api_system_kernel():
    params = {}
    security_keys = [
        "net.ipv4.ip_forward","net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects","net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.all.log_martians","net.ipv4.tcp_syncookies",
        "kernel.randomize_va_space","fs.suid_dumpable"
    ]
    findings = []
    for key in security_keys:
        val = run_cmd(f"sysctl -n {key} 2>/dev/null")
        params[key] = val
    if params.get("net.ipv4.ip_forward") == "1":
        findings.append({"severity":"HIGH","finding":"IP forwarding açık","recommendation":"Gerekli değilse sysctl ile kapatın"})
    if params.get("kernel.randomize_va_space") != "2":
        findings.append({"severity":"HIGH","finding":"ASLR tam aktif değil","recommendation":"kernel.randomize_va_space=2 yapın"})
    if params.get("net.ipv4.tcp_syncookies") != "1":
        findings.append({"severity":"MEDIUM","finding":"SYN cookies aktif değil","recommendation":"SYN flood koruması için aktif edin"})
    risk = "HIGH" if any(f["severity"]=="HIGH" for f in findings) else "MEDIUM" if findings else "LOW"
    return jsonify({"params":params,"findings":findings,"risk_level":risk})

@app.route("/api/system/processes")
def api_system_processes():
    # macOS'taki ps --sort seçeneğini tanımıyor
    ps = run_cmd("ps aux -m | head -25" if IS_MAC else "ps aux --sort=-%mem | head -25")
    return jsonify({"processes":ps,"risk_level":"INFO"})

@app.route("/api/system/disk-encryption")
def api_system_diskenc():
    lsblk = run_cmd("lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT 2>/dev/null")
    crypt = run_cmd("lsblk -o NAME,FSTYPE 2>/dev/null | grep -i crypt || fdesetup status 2>/dev/null || echo 'Kontrol edilemedi'")
    # "Kontrol edilemedi" içinde de "on" geçtiği için daha sıkı kontrol
    low = (crypt or "").lower()
    encrypted = "crypt" in low or "filevault is on" in low
    return jsonify({"block_devices":lsblk,"encryption_status":crypt,"encrypted":encrypted,
                     "risk_level":"CRITICAL" if not encrypted else "LOW"})

# ════════════════════════════════════════════════════════════
#  4. LOG ANALİZİ
# ════════════════════════════════════════════════════════════

@app.route("/api/logs/auth")
def api_logs_auth():
    os_t = platform.system()
    if os_t == "Darwin":
        logs = run_cmd("log show --predicate 'category==\"auth\"' --last 1h 2>/dev/null | tail -60")
    else:
        logs = run_cmd("tail -150 /var/log/auth.log 2>/dev/null || tail -150 /var/log/secure 2>/dev/null || journalctl -u sshd --no-pager -n 60 2>/dev/null || echo 'Log bulunamadı'")
    failed = logs.lower().count("failed") + logs.lower().count("failure") + logs.lower().count("invalid user")
    accepted = logs.lower().count("accepted") + logs.lower().count("session opened")
    brute = failed > 20
    return jsonify({"logs":logs[:8000],"failed_attempts":failed,"successful_logins":accepted,
                     "brute_force_suspected":brute,
                     "risk_level":"CRITICAL" if brute else "HIGH" if failed>10 else "MEDIUM" if failed>3 else "LOW"})

@app.route("/api/logs/system")
def api_logs_system():
    os_t = platform.system()
    if os_t == "Darwin":
        logs = run_cmd("log show --last 30m 2>/dev/null | tail -60")
    else:
        logs = run_cmd("journalctl --no-pager -n 80 --priority=err 2>/dev/null || tail -80 /var/log/syslog 2>/dev/null")
    errors = logs.lower().count("error")
    warnings = logs.lower().count("warning") + logs.lower().count("warn")
    return jsonify({"logs":logs[:8000],"errors":errors,"warnings":warnings,
                     "risk_level":"HIGH" if errors>15 else "MEDIUM" if errors>5 else "LOW"})

@app.route("/api/logs/network")
def api_logs_network():
    fw = run_cmd("tail -80 /var/log/ufw.log 2>/dev/null || echo 'UFW log yok'")
    kern = run_cmd("dmesg 2>/dev/null | grep -i 'net\\|eth\\|wlan\\|link\\|drop\\|reject' | tail -40 || echo 'N/A'")
    blocked = fw.lower().count("block") + kern.lower().count("drop")
    return jsonify({"firewall_logs":fw[:5000],"kernel_logs":kern[:3000],"blocked":blocked,
                     "risk_level":"HIGH" if blocked>30 else "MEDIUM" if blocked>10 else "LOW"})

@app.route("/api/logs/kernel")
def api_logs_kernel():
    dmesg = run_cmd("dmesg --level=err,warn 2>/dev/null | tail -50 || dmesg | tail -50")
    return jsonify({"kernel_logs":dmesg[:5000],"risk_level":"INFO"})

# ════════════════════════════════════════════════════════════
#  5. UYUMLULUK KONTROLÜ (Comprehensive)
# ════════════════════════════════════════════════════════════

@app.route("/api/compliance/full-scan")
def api_compliance_full():
    checks = []

    def add(cat, name, cmd_or_fn, expect_fn, detail_fn, rec, linux_only=False):
        # Linux'a özgü kontroller (sysctl net.ipv4, login.defs, systemd...) macOS
        # ve Windows'ta yanlışlıkla FAIL vermesin, N/A olarak geçsin
        if linux_only and not IS_LINUX:
            checks.append({"category":cat,"check":name,"status":"N/A",
                           "detail":f"{platform.system()} üzerinde uygulanamaz","recommendation":rec,"raw":""})
            return
        if callable(cmd_or_fn):
            val = cmd_or_fn()
        else:
            val = run_cmd(cmd_or_fn)
        passed = expect_fn(val)
        detail = detail_fn(val)
        checks.append({"category":cat,"check":name,"status":"PASS" if passed else "FAIL",
                       "detail":detail,"recommendation":rec,"raw":val[:200] if isinstance(val,str) else str(val)[:200]})

    # --- Access Control ---
    if IS_MAC:
        add("Erişim Kontrol","Firewall Durumu","/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null",
            lambda v: "enabled" in v.lower(), lambda v: "Aktif" if "enabled" in v.lower() else "Aktif değil",
            "Sistem Ayarları > Ağ > Güvenlik Duvarı üzerinden aktif edin")
    else:
        add("Erişim Kontrol","Firewall Durumu","ufw status 2>/dev/null",
            lambda v: "status: active" in v.lower(), lambda v: "Aktif" if "status: active" in v.lower() else "Aktif değil / ufw yok",
            "ufw enable ile aktif edin", linux_only=True)
    add("Erişim Kontrol","SSH Root Girişi","cat /etc/ssh/sshd_config 2>/dev/null",
        lambda v: "PermitRootLogin yes" not in v, lambda v: "Root girişi kapalı" if "PermitRootLogin yes" not in v else "Root girişi açık!",
        "PermitRootLogin no ayarlayın")
    add("Erişim Kontrol","Boş Parola Girişi","cat /etc/ssh/sshd_config 2>/dev/null",
        lambda v: "PermitEmptyPasswords yes" not in v, lambda v: "Kapalı" if "PermitEmptyPasswords yes" not in v else "Açık!",
        "PermitEmptyPasswords no ayarlayın")
    add("Erişim Kontrol","Parola Max Yaş","grep PASS_MAX_DAYS /etc/login.defs 2>/dev/null | grep -v '#' | awk '{print $2}'",
        lambda v: v.isdigit() and int(v)<=90, lambda v: f"{v} gün" if v else "Ayarsız",
        "PASS_MAX_DAYS ≤ 90 ayarlayın", linux_only=True)
    add("Erişim Kontrol","Parola Min Uzunluk","grep PASS_MIN_LEN /etc/login.defs 2>/dev/null | grep -v '#' | awk '{print $2}'",
        lambda v: v.isdigit() and int(v)>=12, lambda v: f"{v} karakter" if v else "Ayarsız",
        "PASS_MIN_LEN ≥ 12 ayarlayın", linux_only=True)

    # --- Network Security ---
    add("Ağ Güvenliği","IP Forwarding","sysctl -n net.ipv4.ip_forward 2>/dev/null",
        lambda v: v == "0", lambda v: "Kapalı" if v=="0" else "Açık",
        "net.ipv4.ip_forward=0 ayarlayın", linux_only=True)
    add("Ağ Güvenliği","SYN Cookies","sysctl -n net.ipv4.tcp_syncookies 2>/dev/null",
        lambda v: v == "1", lambda v: "Aktif" if v=="1" else "Devre dışı",
        "net.ipv4.tcp_syncookies=1 ayarlayın", linux_only=True)
    add("Ağ Güvenliği","ICMP Redirect","sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null",
        lambda v: v == "0", lambda v: "Reddediliyor" if v=="0" else "Kabul ediliyor",
        "ICMP redirect'leri kapatın", linux_only=True)

    # --- System Hardening ---
    add("Sistem Sertleştirme","ASLR","sysctl -n kernel.randomize_va_space 2>/dev/null",
        lambda v: v == "2", lambda v: f"Seviye: {v}" if v else "Kontrol edilemedi",
        "kernel.randomize_va_space=2 ayarlayın", linux_only=True)
    add("Sistem Sertleştirme","/tmp İzinleri","stat -c '%a' /tmp 2>/dev/null",
        lambda v: v == "1777", lambda v: f"İzinler: {v}" if v else "N/A",
        "/tmp sticky bit ayarlayın", linux_only=True)
    add("Sistem Sertleştirme","Core Dump","sysctl -n fs.suid_dumpable 2>/dev/null",
        lambda v: v == "0", lambda v: "Kapalı" if v=="0" else "Açık",
        "fs.suid_dumpable=0 ayarlayın", linux_only=True)

    # --- Data Protection ---
    add("Veri Koruma","Disk Şifreleme",
        "lsblk -o FSTYPE 2>/dev/null | grep -ic crypt || fdesetup status 2>/dev/null",
        lambda v: (v.split() or ["0"])[0].isdigit() and int(v.split()[0]) > 0 or "filevault is on" in v.lower(),
        lambda v: "Şifreli" if ((v.split() or ["0"])[0].isdigit() and int(v.split()[0]) > 0 or "filevault is on" in v.lower()) else "Şifreleme yok/belirsiz",
        "LUKS veya FileVault ile şifreleme aktif edin")

    # --- Patch Management ---
    add("Yama Yönetimi","Otomatik Güncelleme",
        "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>/dev/null",
        lambda v: "1" in v, lambda v: "Aktif" if "1" in v else "Kontrol edilemedi",
        "Otomatik güvenlik güncellemelerini aktif edin")

    # --- Logging & Monitoring ---
    add("Loglama","Audit Daemon","systemctl is-active auditd 2>/dev/null || echo 'inactive'",
        lambda v: "active" in v.lower() and "inactive" not in v.lower(), lambda v: v,
        "auditd servisini aktif edin", linux_only=True)
    add("Loglama","Syslog Servisi","systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog-ng 2>/dev/null || echo 'inactive'",
        lambda v: "active" in v.lower() and "inactive" not in v.lower(), lambda v: v,
        "rsyslog veya syslog-ng aktif edin", linux_only=True)

    passed = len([c for c in checks if c["status"]=="PASS"])
    failed = len([c for c in checks if c["status"]=="FAIL"])
    total = passed + failed   # N/A olanlar skora katılmıyor
    score = int((passed/total)*100) if total else 0
    risk = "CRITICAL" if score<40 else "HIGH" if score<60 else "MEDIUM" if score<80 else "LOW"

    return jsonify({"checks":checks,
                     "summary":{"total":total,"passed":passed,"failed":failed,"score":score,
                                "not_applicable":len(checks)-total},
                     "risk_level":risk})

# ════════════════════════════════════════════════════════════
#  6. VULNERABILITY ASSESSMENT
# ════════════════════════════════════════════════════════════

@app.route("/api/vuln/nmap", methods=["POST"])
def api_vuln_nmap():
    d = request.json or {}
    target = d.get("target","127.0.0.1")
    scan_type = d.get("scan_type","basic")
    if not gecerli_hedef(target):
        return jsonify({"error":"Geçersiz hedef"}), 400
    nmap_check = run_cmd("which nmap 2>/dev/null")
    if not nmap_check:
        return jsonify({"error":"Nmap yüklü değil. Kurulum: sudo apt install nmap","risk_level":"INFO"})
    cmd_map = {
        "basic": f"nmap -sV -T4 {target}",
        "aggressive": f"nmap -A -T4 {target}",
        "vuln": f"nmap --script vuln -T4 {target}",
        "full": f"nmap -sV -sC -O -T4 -p- {target}",
        "udp": f"nmap -sU -T4 --top-ports 100 {target}",
        "stealth": f"nmap -sS -T2 {target}"
    }
    cmd = cmd_map.get(scan_type, cmd_map["basic"])
    output = run_cmd(cmd, timeout=120)
    open_count = output.count("/tcp") + output.count("/udp")
    vulns = output.lower().count("vulnerable") + output.lower().count("vuln")
    risk = "CRITICAL" if vulns>0 else "HIGH" if open_count>20 else "MEDIUM" if open_count>10 else "LOW"
    return jsonify({"target":target,"scan_type":scan_type,"output":output[:10000],
                     "open_services":open_count,"vulnerabilities_found":vulns,"risk_level":risk})

@app.route("/api/vuln/os-cve")
def api_vuln_oscve():
    kernel = run_cmd("uname -r")
    os_release = run_cmd("cat /etc/os-release 2>/dev/null | head -5")
    pkg_count = run_cmd("dpkg -l 2>/dev/null | wc -l || rpm -qa 2>/dev/null | wc -l")
    security = run_cmd("apt list --upgradable 2>/dev/null | grep -i security | head -10")
    return jsonify({"kernel":kernel,"os_release":os_release,"installed_packages":pkg_count,
                     "security_updates":security or "Yok","risk_level":"MEDIUM" if security else "LOW"})

# ════════════════════════════════════════════════════════════
#  7. CISA-UYUMLU RAPOR OLUŞTURUCU
# ════════════════════════════════════════════════════════════

@app.route("/api/report/generate", methods=["POST"])
def api_report_generate():
    d = request.json or {}
    auditor_name = e(d.get("auditor","IT Auditor"))[:120]
    org_name = e(d.get("organization","Kurum Adı"))[:120]
    scope = e(d.get("scope","Genel IT Denetimi"))[:200]
    report_type = d.get("report_type","full")

    now = datetime.datetime.now()
    hostname = e(socket.gethostname())
    os_info = e(f"{platform.system()} {platform.release()}")

    # Compliance verisi topla
    comp_data = None
    try:
        with app.test_request_context():
            resp = api_compliance_full()
            comp_data = resp.get_json()
    except: pass

    # ── CISA Risk Matrisi ──
    risk_matrix_html = """
    <div class="risk-matrix">
        <h3>Risk Değerlendirme Matrisi (CISA Çerçevesi)</h3>
        <table class="matrix-table">
            <tr><th></th><th>Düşük Etki</th><th>Orta Etki</th><th>Yüksek Etki</th><th>Kritik Etki</th></tr>
            <tr><th>Yüksek Olasılık</th><td class="risk-m">ORTA</td><td class="risk-h">YÜKSEK</td><td class="risk-c">KRİTİK</td><td class="risk-c">KRİTİK</td></tr>
            <tr><th>Orta Olasılık</th><td class="risk-l">DÜŞÜK</td><td class="risk-m">ORTA</td><td class="risk-h">YÜKSEK</td><td class="risk-c">KRİTİK</td></tr>
            <tr><th>Düşük Olasılık</th><td class="risk-l">DÜŞÜK</td><td class="risk-l">DÜŞÜK</td><td class="risk-m">ORTA</td><td class="risk-h">YÜKSEK</td></tr>
        </table>
    </div>
    """

    # ── Bulgu Templatei ──
    findings_html = ""
    finding_counter = 1
    if comp_data:
        for check in comp_data.get("checks",[]):
            if check["status"] == "FAIL":
                impact = "Yüksek" if check.get("category") in ["Erişim Kontrol","Ağ Güvenliği"] else "Orta"
                probability = "Yüksek" if check.get("category") == "Erişim Kontrol" else "Orta"
                risk_rating = "Kritik" if impact=="Yüksek" and probability=="Yüksek" else "Yüksek" if impact=="Yüksek" or probability=="Yüksek" else "Orta"
                findings_html += f"""
                <div class="finding-block">
                    <div class="finding-header">
                        <span class="finding-id">BULGU-{finding_counter:03d}</span>
                        <span class="finding-risk risk-tag-{risk_rating.lower()}">{risk_rating} Risk</span>
                    </div>
                    <table class="finding-table">
                        <tr><th>Bulgu Başlığı</th><td>{e(check['check'])}</td></tr>
                        <tr><th>Kategori</th><td>{e(check['category'])}</td></tr>
                        <tr><th>Durum</th><td>{e(check['detail'])}</td></tr>
                        <tr><th>Etki (Impact)</th><td>{impact}</td></tr>
                        <tr><th>Olasılık (Likelihood)</th><td>{probability}</td></tr>
                        <tr><th>Risk Derecesi</th><td><strong>{risk_rating}</strong></td></tr>
                        <tr><th>CISA Domain</th><td>Domain 5 — Bilgi Varlıklarının Korunması</td></tr>
                        <tr><th>Referans Standart</th><td>ISO 27001 A.12 / COBIT DSS05 / NIST SP 800-53</td></tr>
                        <tr><th>Öneri (Recommendation)</th><td>{e(check['recommendation'])}</td></tr>
                        <tr><th>Yönetim Yanıtı</th><td style="color:#888;font-style:italic;">[Yönetim tarafından doldurulacak]</td></tr>
                        <tr><th>Hedef Tarih</th><td style="color:#888;font-style:italic;">[Belirlenmesi gereken]</td></tr>
                        <tr><th>Sorumlu</th><td style="color:#888;font-style:italic;">[Atanması gereken]</td></tr>
                    </table>
                </div>
                """
                finding_counter += 1

    # ── Compliance özet ──
    score = comp_data["summary"]["score"] if comp_data else 0
    passed = comp_data["summary"]["passed"] if comp_data else 0
    failed = comp_data["summary"]["failed"] if comp_data else 0
    total = comp_data["summary"]["total"] if comp_data else 0

    score_color = "#00c853" if score>=80 else "#ff9100" if score>=50 else "#ff1744"

    report_html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>CISA IT Denetim Raporu — {now.strftime('%Y-%m-%d')}</title>
<style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&family=DM+Mono:wght@400;500&display=swap');

    :root {{
        --bg: #0b0e14; --card: #12161f; --border: #1e2533;
        --text: #cdd6e4; --muted: #5a6a85; --accent: #38bdf8;
        --green: #00c853; --red: #ff1744; --orange: #ff9100; --yellow: #ffd600;
    }}
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{ font-family:'DM Sans',sans-serif; background:var(--bg); color:var(--text); padding:50px; line-height:1.7; }}
    .container {{ max-width:900px; margin:0 auto; }}

    /* Cover */
    .cover {{ text-align:center; padding:80px 40px; border:1px solid var(--border); border-radius:16px; margin-bottom:50px; background: linear-gradient(135deg, #0b0e14, #161d2e); }}
    .cover h1 {{ font-size:32px; color:var(--accent); margin-bottom:8px; }}
    .cover h2 {{ font-size:18px; color:var(--muted); font-weight:400; }}
    .cover .meta {{ margin-top:30px; font-size:13px; color:var(--muted); }}
    .cover .meta span {{ display:block; margin:4px 0; }}
    .cover .classification {{ display:inline-block; margin-top:20px; padding:6px 20px; border:2px solid var(--red); color:var(--red); border-radius:8px; font-weight:700; font-size:13px; letter-spacing:2px; }}

    /* Sections */
    .section {{ margin-bottom:40px; }}
    .section h2 {{ font-size:20px; color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:10px; margin-bottom:20px; }}
    .section h3 {{ font-size:16px; color:var(--text); margin:16px 0 8px; }}
    .section p, .section li {{ font-size:14px; color:var(--text); }}
    .section ul {{ padding-left:20px; }}
    .section li {{ margin-bottom:6px; }}

    /* Score */
    .score-box {{ text-align:center; padding:30px; background:var(--card); border:1px solid var(--border); border-radius:16px; margin:20px 0; }}
    .score-num {{ font-size:64px; font-weight:700; font-family:'DM Mono',monospace; }}
    .score-bar {{ width:100%; height:12px; background:var(--border); border-radius:6px; margin:16px 0; overflow:hidden; }}
    .score-fill {{ height:100%; border-radius:6px; transition:width 1s; }}

    /* Matrix */
    .risk-matrix {{ margin:20px 0; }}
    .matrix-table {{ width:100%; border-collapse:collapse; font-size:13px; }}
    .matrix-table th, .matrix-table td {{ border:1px solid var(--border); padding:10px; text-align:center; }}
    .matrix-table th {{ background:var(--card); color:var(--muted); font-weight:500; }}
    .risk-c {{ background:rgba(255,23,68,0.15); color:var(--red); font-weight:700; }}
    .risk-h {{ background:rgba(255,145,0,0.15); color:var(--orange); font-weight:700; }}
    .risk-m {{ background:rgba(255,214,0,0.15); color:var(--yellow); font-weight:700; }}
    .risk-l {{ background:rgba(0,200,83,0.15); color:var(--green); font-weight:700; }}

    /* Findings */
    .finding-block {{ background:var(--card); border:1px solid var(--border); border-radius:12px; margin-bottom:20px; overflow:hidden; }}
    .finding-header {{ display:flex; justify-content:space-between; align-items:center; padding:14px 20px; border-bottom:1px solid var(--border); }}
    .finding-id {{ font-family:'DM Mono',monospace; font-weight:700; color:var(--accent); }}
    .risk-tag-kritik {{ background:rgba(255,23,68,0.15); color:var(--red); padding:4px 12px; border-radius:20px; font-size:12px; font-weight:700; }}
    .risk-tag-yüksek {{ background:rgba(255,145,0,0.15); color:var(--orange); padding:4px 12px; border-radius:20px; font-size:12px; font-weight:700; }}
    .risk-tag-orta {{ background:rgba(255,214,0,0.15); color:var(--yellow); padding:4px 12px; border-radius:20px; font-size:12px; font-weight:700; }}
    .finding-table {{ width:100%; border-collapse:collapse; }}
    .finding-table th {{ text-align:left; padding:10px 20px; width:200px; color:var(--muted); font-size:13px; font-weight:500; border-bottom:1px solid rgba(30,37,51,0.5); background:rgba(0,0,0,0.2); }}
    .finding-table td {{ padding:10px 20px; font-size:13px; border-bottom:1px solid rgba(30,37,51,0.5); }}

    /* Stats */
    .stats-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:20px 0; }}
    .stat {{ text-align:center; padding:20px; background:var(--card); border:1px solid var(--border); border-radius:12px; }}
    .stat .val {{ font-size:28px; font-weight:700; font-family:'DM Mono',monospace; }}
    .stat .lbl {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-top:4px; }}

    /* Compliance table */
    .comp-table {{ width:100%; border-collapse:collapse; font-size:13px; margin:16px 0; }}
    .comp-table th {{ text-align:left; padding:10px 14px; color:var(--muted); font-weight:500; border-bottom:1px solid var(--border); }}
    .comp-table td {{ padding:10px 14px; border-bottom:1px solid rgba(30,37,51,0.5); }}
    .status-pass {{ color:var(--green); font-weight:700; }}
    .status-fail {{ color:var(--red); font-weight:700; }}

    /* Print */
    @media print {{
        body {{ background:white; color:#222; padding:20px; }}
        .cover {{ border-color:#ddd; background:white; }}
        .cover h1 {{ color:#0066cc; }}
        .finding-block, .stat, .score-box {{ border-color:#ddd; background:#fafafa; }}
        .matrix-table th, .matrix-table td {{ border-color:#ccc; }}
    }}

    .page-break {{ page-break-before: always; margin-top: 40px; }}
    .footer {{ text-align:center; padding:30px; color:var(--muted); font-size:12px; border-top:1px solid var(--border); margin-top:50px; }}
</style>
</head>
<body>
<div class="container">

    <!-- KAPAK -->
    <div class="cover">
        <h1>BİLGİ SİSTEMLERİ DENETİM RAPORU</h1>
        <h2>{org_name}</h2>
        <div class="meta">
            <span>Rapor Tarihi: {now.strftime('%d/%m/%Y %H:%M')}</span>
            <span>Denetçi: {auditor_name}</span>
            <span>Kapsam: {scope}</span>
            <span>Hedef Sistem: {hostname} ({os_info})</span>
            <span>Referans: CISA Review Manual / COBIT 2019 / ISO 27001 / NIST SP 800-53</span>
        </div>
        <div class="classification">GİZLİ — SADECE YETKİLİ KİŞİLER İÇİN</div>
    </div>

    <!-- YÖNETİCİ ÖZETİ -->
    <div class="section">
        <h2>1. Yönetici Özeti (Executive Summary)</h2>
        <p>Bu rapor, {org_name} kapsamında incelenen sistemin ({hostname}) teknik güvenlik kontrollerinin otomatik tarama sonuçlarını içermektedir. Kontroller ağırlıklı olarak CISA Domain 4 (Bilgi Sistemleri Operasyonları) ve Domain 5 (Bilgi Varlıklarının Korunması) konularını kapsar; yönetişim ve süreç kontrolleri (Domain 1-3) bu taramanın kapsamı dışındadır ve ayrıca değerlendirilmelidir. Platforma uygulanamayan kontroller N/A olarak gösterilmiş ve skora dahil edilmemiştir.</p>
        <p>Denetim sonucunda toplam <strong>{total}</strong> kontrol gerçekleştirilmiş, bunlardan <strong>{passed}</strong> adedi başarılı, <strong>{failed}</strong> adedi başarısız olarak değerlendirilmiştir.</p>

        <div class="score-box">
            <div class="score-num" style="color:{score_color}">{score}%</div>
            <div style="color:var(--muted);font-size:13px;">Genel Uyumluluk Skoru</div>
            <div class="score-bar"><div class="score-fill" style="width:{score}%;background:{score_color};"></div></div>
        </div>

        <div class="stats-grid">
            <div class="stat"><div class="val">{total}</div><div class="lbl">Toplam Kontrol</div></div>
            <div class="stat"><div class="val" style="color:var(--green)">{passed}</div><div class="lbl">Başarılı</div></div>
            <div class="stat"><div class="val" style="color:var(--red)">{failed}</div><div class="lbl">Başarısız</div></div>
            <div class="stat"><div class="val" style="color:{score_color}">{score}%</div><div class="lbl">Skor</div></div>
        </div>
    </div>

    <!-- DENETİM KAPSAMI -->
    <div class="section">
        <h2>2. Denetim Kapsamı ve Metodoloji</h2>
        <h3>2.1 CISA Domainleri</h3>
        <ul>
            <li><strong>Domain 1:</strong> Bilgi Sistemleri Denetim Süreci</li>
            <li><strong>Domain 2:</strong> IT Yönetişim ve Yönetimi</li>
            <li><strong>Domain 3:</strong> Bilgi Sistemleri Edinimi, Geliştirme ve Uygulama</li>
            <li><strong>Domain 4:</strong> Bilgi Sistemleri Operasyonları ve İş Dayanıklılığı</li>
            <li><strong>Domain 5:</strong> Bilgi Varlıklarının Korunması</li>
        </ul>
        <h3>2.2 Referans Standartlar</h3>
        <ul>
            <li>ISACA CISA Review Manual (28th Edition)</li>
            <li>COBIT 2019 Framework</li>
            <li>ISO/IEC 27001:2022</li>
            <li>NIST Special Publication 800-53 Rev. 5</li>
            <li>CIS Critical Security Controls v8</li>
        </ul>
        <h3>2.3 Risk Değerlendirme Metodolojisi</h3>
        <p>Bulgular, ISACA'nın risk değerlendirme çerçevesine uygun olarak Etki (Impact) ve Olasılık (Likelihood) matrisine göre derecelendirilmiştir:</p>
        {risk_matrix_html}
    </div>

    <!-- UYUMLULUK DETAY -->
    <div class="section page-break">
        <h2>3. Uyumluluk Kontrol Sonuçları</h2>
        <table class="comp-table">
            <tr><th>Kategori</th><th>Kontrol</th><th>Sonuç</th><th>Detay</th></tr>"""

    if comp_data:
        for c in comp_data.get("checks",[]):
            cls = "status-pass" if c["status"]=="PASS" else "status-fail" if c["status"]=="FAIL" else ""
            report_html += f'<tr><td>{e(c["category"])}</td><td>{e(c["check"])}</td><td class="{cls}">{c["status"]}</td><td>{e(c["detail"])}</td></tr>'

    report_html += f"""
        </table>
    </div>

    <!-- BULGULAR -->
    <div class="section page-break">
        <h2>4. Denetim Bulguları ve Öneriler</h2>
        <p>Aşağıda tespit edilen bulgular, CISA risk değerlendirme metodolojisine göre sınıflandırılmıştır. Her bulgu için etki analizi, olasılık değerlendirmesi, referans standart ve düzeltici eylem önerisi sunulmuştur.</p>
        {findings_html if findings_html else '<p style="color:var(--green);">Başarısız kontrol tespit edilmedi.</p>'}
    </div>

    <!-- SONUÇ -->
    <div class="section page-break">
        <h2>5. Sonuç ve Genel Değerlendirme</h2>
        <p>Gerçekleştirilen denetim sonucunda, hedef sistemin genel uyumluluk skoru <strong>%{score}</strong> olarak belirlenmiştir.</p>
        <p>{'Sistemde kritik güvenlik açıkları tespit edilmiştir. Acil düzeltici aksiyonlar alınması gerekmektedir.' if score < 60 else 'Sistemde bazı iyileştirme alanları tespit edilmiştir. Önerilen düzeltici aksiyonların planlanması tavsiye edilir.' if score < 80 else 'Sistem genel olarak güvenlik standartlarına uygun durumdadır. Minor iyileştirmeler önerilmektedir.'}</p>
        <h3>5.1 Öncelikli Aksiyonlar</h3>
        <ul>
            <li>Kritik bulgular 30 gün içinde çözülmelidir</li>
            <li>Yüksek riskli bulgular 60 gün içinde ele alınmalıdır</li>
            <li>Orta riskli bulgular 90 gün içinde planlanmalıdır</li>
            <li>Düşük riskli bulgular bir sonraki denetim dönemine kadar değerlendirilmelidir</li>
        </ul>
        <h3>5.2 Takip Denetimi</h3>
        <p>Kritik ve yüksek riskli bulguların düzeltilmesini doğrulamak üzere 90 gün içinde takip denetimi planlanmalıdır.</p>
    </div>

    <!-- İMZA -->
    <div class="section" style="margin-top:60px;">
        <h2>6. Onay</h2>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:40px;margin-top:30px;">
            <div style="border-top:1px solid var(--border);padding-top:12px;">
                <p style="font-weight:700;">Denetçi</p>
                <p style="color:var(--muted);font-size:13px;">{auditor_name}</p>
                <p style="color:var(--muted);font-size:13px;">Tarih: {now.strftime('%d/%m/%Y')}</p>
            </div>
            <div style="border-top:1px solid var(--border);padding-top:12px;">
                <p style="font-weight:700;">Denetim Yöneticisi</p>
                <p style="color:var(--muted);font-size:13px;">[İsim]</p>
                <p style="color:var(--muted);font-size:13px;">Tarih: ___/___/______</p>
            </div>
        </div>
    </div>

    <div class="footer">
        <p>Bu rapor CISA IT Audit Toolkit ile otomatik oluşturulmuştur. Otomatik tarama sonuçları denetçi tarafından doğrulanmadan nihai bulgu olarak kullanılmamalıdır.</p>
        <p>Rapor ID: RPT-{now.strftime('%Y%m%d%H%M%S')}-{hashlib.md5(hostname.encode()).hexdigest()[:8].upper()}</p>
        <p>GİZLİLİK: Bu belge sadece yetkili kişiler tarafından görüntülenmelidir.</p>
    </div>

</div>
</body>
</html>"""

    # Dosyaya kaydet
    fname = f"audit_report_{now.strftime('%Y%m%d_%H%M%S')}.html"
    fpath = REPORTS_DIR / fname
    fpath.write_text(report_html, encoding="utf-8")

    return jsonify({"filename":fname,"path":str(fpath),"score":score,"findings_count":finding_counter-1})

@app.route("/api/report/download/<filename>")
def api_report_download(filename):
    fpath = (REPORTS_DIR / filename).resolve()
    if fpath.parent == REPORTS_DIR.resolve() and fpath.suffix == ".html" and fpath.exists():
        return send_file(str(fpath), as_attachment=True, download_name=filename)
    return jsonify({"error":"Rapor bulunamadı"}), 404

@app.route("/api/report/list")
def api_report_list():
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.html"), reverse=True):
        reports.append({"filename":f.name,"size":f.stat().st_size,
                        "created":datetime.datetime.fromtimestamp(f.stat().st_ctime).isoformat()})
    return jsonify({"reports":reports})

# ════════════════════════════════════════════════════════════
#  BAŞLATMA
# ════════════════════════════════════════════════════════════

def bos_port(tercih):
    # macOS 12+ 5000 portunu AirPlay Alıcısı için kullanıyor; varsayılan 5050,
    # o da doluysa sistemin verdiği boş bir port
    try:
        with socket.socket() as so:
            so.bind(("127.0.0.1", tercih))
        return tercih
    except OSError:
        with socket.socket() as so:
            so.bind(("127.0.0.1", 0))
            return so.getsockname()[1]

if __name__ == "__main__":
    import argparse, webbrowser
    ap = argparse.ArgumentParser(description="CISA IT Audit Toolkit")
    ap.add_argument("--web", action="store_true", help="pencere yerine tarayıcıda aç")
    ap.add_argument("--no-open", action="store_true", help="tarayıcıyı otomatik açma")
    ap.add_argument("--port", type=int, default=5050)
    args = ap.parse_args()
    port = bos_port(args.port)
    if port != args.port:
        print(f"{args.port} portu kullanımda, {port} kullanılacak.")
    url = f"http://127.0.0.1:{port}"

    def start_flask():
        app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)

    webview = None
    if not args.web:
        try:
            import webview
        except ImportError:
            print("pywebview kurulu değil, tarayıcı modunda açılıyor.")

    print(f"CISA IT Audit Toolkit: {url}  (kapatmak için Ctrl+C)")
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    time.sleep(1.2)
    if webview is not None:
        try:
            webview.create_window("CISA IT Audit Toolkit", url, width=1400, height=900,
                                  min_size=(1100, 700), background_color="#0b0e14")
            webview.start()
            raise SystemExit(0)
        except SystemExit:
            raise
        except Exception as ex:
            print(f"Pencere açılamadı ({ex}), tarayıcıdan devam edin: {url}")
    if not args.no_open:
        try: webbrowser.open(url)
        except Exception: pass
    try:
        while flask_thread.is_alive(): time.sleep(1)
    except KeyboardInterrupt:
        print("Kapatıldı.")
