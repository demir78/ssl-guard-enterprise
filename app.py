import ssl
import socket
import datetime
import smtplib
import requests
import os
import threading
import json
import concurrent.futures
import re
import csv
import sqlite3
import whois
import openpyxl # YENİ: Gerçek Excel (.xlsx) dosyaları oluşturmak için eklendi
from dateutil import parser as date_parser
from io import StringIO, BytesIO # YENİ: BytesIO eklendi
from urllib.parse import urlparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template_string, request, redirect, url_for, jsonify, flash, Response, session
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID

app = Flask(__name__)
# Oturum güvenliği için secret_key gereklidir
app.secret_key = "kurumsal_super_gizli_anahtar_soc_2026"

DATA_DIR = "data"
DB_FILE = f"{DATA_DIR}/ssl_guard.db"

scan_results = []
whois_results = [] 
last_scan_time = "Henüz tarama yapılmadı"
is_scanning = False 
scan_trigger = threading.Event()

# --- VERİTABANI YÖNETİMİ (SQLITE) ---
def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
    conn.row_factory = dict_factory
    return conn

def init_db():
    ensure_data_dir()
    with get_db() as conn:
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS settings (
                        id INTEGER PRIMARY KEY,
                        alert_days_warning INTEGER,
                        alert_days_critical INTEGER,
                        alert_days_urgent INTEGER,
                        mail_to TEXT,
                        smtp_server TEXT,
                        smtp_port INTEGER,
                        smtp_user TEXT,
                        smtp_pass TEXT,
                        webhook_url TEXT,
                        admin_user TEXT,
                        admin_pass TEXT
                    )''')
        
        c.execute("SELECT COUNT(*) as count FROM settings")
        if c.fetchone()['count'] == 0:
            default_hash = generate_password_hash("admin123")
            c.execute('''INSERT INTO settings 
                         (id, alert_days_warning, alert_days_critical, alert_days_urgent, smtp_server, smtp_port, mail_to, smtp_user, smtp_pass, webhook_url, admin_user, admin_pass)
                         VALUES (1, 30, 15, 7, 'smtp.office365.com', 587, '', '', '', '', 'admin', ?)''', (default_hash,))
            
        try:
            c.execute("ALTER TABLE settings ADD COLUMN admin_user TEXT DEFAULT 'admin'")
            c.execute(f"ALTER TABLE settings ADD COLUMN admin_pass TEXT DEFAULT '{generate_password_hash('admin123')}'")
        except sqlite3.OperationalError:
            pass

        c.execute('CREATE TABLE IF NOT EXISTS domains (domain_name TEXT PRIMARY KEY)')
        c.execute('CREATE TABLE IF NOT EXISTS cache (domain_name TEXT PRIMARY KEY, subdomains_json TEXT)')
        conn.commit()

def load_settings():
    with get_db() as conn:
        row = conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
        return dict(row) if row else {}

def get_domains():
    with get_db() as conn:
        rows = conn.execute("SELECT domain_name FROM domains").fetchall()
        return [r['domain_name'] for r in rows]

# --- OTURUM KORUMASI (LOGIN) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- BAĞIMSIZ WHOIS MOTORU (TRABIS Destekli) ---
def get_domain_expiry_date(domain_name):
    if domain_name.endswith(".tr"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(("whois.trabis.gov.tr", 43))
            s.send(f"{domain_name}\r\n".encode('utf-8'))
            response = b""
            while True:
                data = s.recv(4096)
                if not data: break
                response += data
            s.close()
            text = response.decode('utf-8', errors='ignore')
            
            match = re.search(r"(?i)(Expires on|Bitiş Tarihi)[.\s:]+([0-9A-Za-z\-]+)", text)
            if match:
                date_str = match.group(2).strip()
                tr_months = {'Oca':'Jan', 'Şub':'Feb', 'Mar':'Mar', 'Nis':'Apr', 'May':'May', 'Haz':'Jun', 'Tem':'Jul', 'Ağu':'Aug', 'Eyl':'Sep', 'Eki':'Oct', 'Kas':'Nov', 'Ara':'Dec'}
                for tr, en in tr_months.items(): date_str = date_str.replace(tr, en)
                return date_parser.parse(date_str, fuzzy=True)
        except Exception: pass

    try:
        w = whois.whois(domain_name)
        exp_date = w.expiration_date
        if isinstance(exp_date, list): exp_date = exp_date[0]
        if isinstance(exp_date, datetime.datetime): return exp_date
        if isinstance(exp_date, str): return date_parser.parse(exp_date, fuzzy=True)
    except Exception: pass

    try:
        r = requests.get(f"https://rdap.org/domain/{domain_name}", timeout=10)
        if r.status_code == 200:
            for event in r.json().get('events', []):
                if event.get('eventAction') == 'expiration':
                    date_str = event.get('eventDate')
                    if date_str: return date_parser.parse(date_str)
    except Exception: pass

    try:
        r = requests.get(f"https://api.hackertarget.com/whois/?q={domain_name}", timeout=10)
        if r.status_code == 200:
            match = re.search(r"(?i)(Registry Expiry Date|Expiration Date|Expiry Date|Expires on):\s*(.+)", r.text)
            if match: return date_parser.parse(match.group(2).strip(), fuzzy=True)
    except Exception: pass
    
    return None

# --- ÇEKİRDEK FONKSİYONLAR ---
def check_https_access(hostname):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        result = sock.connect_ex((hostname, 443))
        sock.close()
        return result == 0
    except:
        return False

def get_subdomains(domain):
    print(f"\n[*] {domain} için Kurumsal OSINT Ağı başlatıldı...")
    subdomains = set([domain])
    with get_db() as conn:
        row = conn.execute("SELECT subdomains_json FROM cache WHERE domain_name=?", (domain,)).fetchone()
        if row and row['subdomains_json']:
            cached_list = json.loads(row['subdomains_json'])
            subdomains.update(cached_list)
        
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    try:
        google_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7'
        }
        r = requests.get(f"https://www.google.com/search?q=site:*.{domain}&num=100", headers=google_headers, timeout=15)
        if r.status_code == 200:
            pattern = r'([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')'
            matches = re.findall(pattern, r.text)
            for match in matches:
                clean_match = match.lower().strip()
                if clean_match.startswith("www."): clean_match = clean_match[4:]
                if '*' not in clean_match and clean_match != domain: subdomains.add(clean_match)
    except Exception: pass

    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", headers=headers, timeout=15)
        if r.status_code == 200:
            for entry in r.json():
                names = entry['name_value'].split('\n')
                for name in names:
                    name = name.strip()
                    if '*' not in name and name: subdomains.add(name)
    except Exception: pass

    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", headers=headers, timeout=15)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.split('\n'):
                if ',' in line:
                    sub = line.split(',')[0].strip()
                    if sub.endswith(domain) and '*' not in sub: subdomains.add(sub)
    except Exception: pass

    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", headers=headers, timeout=15)
        if r.status_code == 200:
            for entry in r.json().get('passive_dns', []):
                name = entry.get('hostname', '').strip()
                if name.endswith(domain) and '*' not in name: subdomains.add(name)
    except Exception: pass

    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 200:
            data = r.json()
            if len(data) > 1: 
                for row in data[1:]:
                    try:
                        parsed = urlparse(row[0])
                        netloc = parsed.netloc.split(':')[0].lower() 
                        if netloc.endswith(domain) and '*' not in netloc: subdomains.add(netloc)
                    except: pass
    except Exception: pass

    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO cache (domain_name, subdomains_json) VALUES (?, ?)", 
                     (domain, json.dumps(list(subdomains))))
        conn.commit()
        
    print(f"[+] {domain} için toplam {len(subdomains)} eşsiz adres analize gönderiliyor.\n")
    return list(subdomains)

def get_ssl_expiry_date(hostname):
    strict_context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10.0) as sock:
            with strict_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return {"date": expire_date, "trusted": True, "error": None}
                
    except ssl.SSLCertVerificationError:
        raw_context = ssl.create_default_context()
        raw_context.check_hostname = False
        raw_context.verify_mode = ssl.CERT_NONE 
        try:
            with socket.create_connection((hostname, 443), timeout=10.0) as sock:
                with raw_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    valid_names = []
                    try:
                        ext = x509_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        valid_names.extend(ext.value.get_values_for_type(x509.DNSName))
                    except x509.ExtensionNotFound: pass
                        
                    for attr in x509_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                        if isinstance(attr.value, str): valid_names.append(attr.value)
                            
                    matched = False
                    target = hostname.lower()
                    for name in valid_names:
                        name = name.lower()
                        if target == name: matched = True; break
                        if name.startswith('*.'):
                            suffix = name[1:] 
                            if target.endswith(suffix):
                                prefix = target[:-len(suffix)]
                                if '.' not in prefix: matched = True; break
                    
                    if not matched: return {"date": x509_cert.not_valid_after, "trusted": False, "error": "İsim Uyuşmuyor"}
                    if x509_cert.issuer == x509_cert.subject: return {"date": x509_cert.not_valid_after, "trusted": False, "error": "Self-Signed CA"}
                    
                    return {"date": x509_cert.not_valid_after, "trusted": True, "error": None}
        except Exception as e: return {"date": None, "trusted": False, "error": f"Hata: {e.__class__.__name__}"}
    except Exception as e: return {"date": None, "trusted": False, "error": f"Bağlantı Hatası: {e.__class__.__name__}"}

def send_notifications(expiring_domains, settings):
    if not expiring_domains: return
    
    if settings.get('smtp_server') and settings.get('mail_to'):
        msg = MIMEMultipart('alternative')
        msg['From'] = settings['smtp_user']
        msg['To'] = settings['mail_to']
        msg['Subject'] = "🚨 Kritik Uyarı: Altyapı Varlık Bitiş Bildirimi (SSL/WHOIS)"
        
        html_body = """
        <!DOCTYPE html>
        <html>
        <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #333; background-color: #f4f7f6; padding: 20px; margin: 0;">
            <div style="max-width: 600px; margin: 0 auto; background: #fff; padding: 25px; border-radius: 8px; border-top: 5px solid #d9534f; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
                <h2 style="color: #d9534f; margin-top: 0; padding-bottom: 10px; border-bottom: 1px solid #eee;">🚨 Altyapı Kritik Uyarısı</h2>
                <p style="font-size: 15px; line-height: 1.5;">Aşağıdaki kurumsal varlıkların SSL / Domain süreleri kritik eşiğin altındadır:</p>
                
                <table style="width: 100%; border-collapse: collapse; margin-top: 20px; margin-bottom: 20px;">
                    <thead>
                        <tr style="background-color: #f8f9fa;">
                            <th style="padding: 12px; text-align: left; border: 1px solid #ddd; color: #555;">Varlık Tipi / Adı</th>
                            <th style="padding: 12px; text-align: center; border: 1px solid #ddd; color: #555;">Kalan Gün</th>
                            <th style="padding: 12px; text-align: left; border: 1px solid #ddd; color: #555;">Bitiş Tarihi</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for item in expiring_domains:
            days = item.get('days_left', 0)
            urg_days = int(settings.get('alert_days_urgent', 7))
            color = "#d9534f" if isinstance(days, int) and days <= urg_days else "#f0ad4e"
            html_body += f"""
                        <tr>
                            <td style="padding: 12px; border: 1px solid #ddd;"><strong>{item['domain']}</strong></td>
                            <td style="padding: 12px; text-align: center; border: 1px solid #ddd; color: {color}; font-weight: bold; font-size: 16px;">{days}</td>
                            <td style="padding: 12px; border: 1px solid #ddd;">{item['expire_date']}</td>
                        </tr>
            """
        html_body += """
                    </tbody>
                </table>
                <div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee; font-size: 12px; color: #888; text-align: center;">
                    <p style="margin: 0;">Bu otomatik bir bilgilendirme mesajıdır.</p>
                </div>
            </div>
        </body>
        </html>
        """
        msg.attach(MIMEText(html_body, 'html'))
        try:
            server = smtplib.SMTP(settings['smtp_server'], int(settings['smtp_port']), timeout=15)
            server.starttls()
            server.login(settings['smtp_user'], settings['smtp_pass'])
            server.send_message(msg)
            server.quit()
        except Exception as e: print(f"[-] Mail hatası: {e}")

    if settings.get('webhook_url'):
        try:
            message = "🚨 **SSL Guard Pro - Kritik Varlık Uyarısı** 🚨\n\n"
            for item in expiring_domains:
                message += f"• **{item['domain']}** (Kalan: {item['days_left']} gün)\n"
            requests.post(settings['webhook_url'], json={"text": message}, timeout=10)
        except Exception as e: print(f"[-] Webhook hatası: {e}")

# --- ARKA PLAN SERVİSİ ---
def background_scanner():
    global scan_results, whois_results, last_scan_time, is_scanning
    init_db()
    
    while True:
        is_scanning = True
        try:
            temp_results = []
            temp_whois_results = []
            expiring_entities = []
            now = datetime.datetime.utcnow()
            domains = get_domains()
            settings = load_settings()
            
            try:
                warn_days = int(settings.get('alert_days_warning', 30))
                crit_days = int(settings.get('alert_days_critical', 15))
                urg_days = int(settings.get('alert_days_urgent', 7))
            except:
                warn_days, crit_days, urg_days = 30, 15, 7

            if domains:
                for root_domain in domains:
                    # 1. BAĞIMSIZ WHOIS KONTROLÜ
                    try:
                        whois_exp = get_domain_expiry_date(root_domain)
                        if whois_exp:
                            if whois_exp.tzinfo is not None:
                                whois_exp = whois_exp.replace(tzinfo=None)
                                
                            w_days_left = (whois_exp - now).days
                            w_status = "OK"
                            if w_days_left <= urg_days: w_status = "ACİL"
                            elif w_days_left <= crit_days: w_status = "CRITICAL"
                            elif w_days_left <= warn_days: w_status = "WARNING"
                            
                            if w_status != "OK":
                                expiring_entities.append({"domain": f"[WHOIS] {root_domain}", "days_left": w_days_left, "expire_date": whois_exp.strftime('%Y-%m-%d')})
                                
                            temp_whois_results.append({"domain": root_domain, "days_left": w_days_left, "expire_date": whois_exp.strftime('%Y-%m-%d'), "status": w_status})
                        else:
                            temp_whois_results.append({"domain": root_domain, "days_left": "?", "expire_date": "Sorgulanamadı (Erişim Yok)", "status": "ERROR"})
                    except Exception as e:
                        print(f"[-] WHOIS Modülü Hatası ({root_domain}): {e}")

                    # 2. MEVCUT SSL TARAMASI
                    subdomains = get_subdomains(root_domain)
                    def process_sub(sub):
                        if check_https_access(sub): return sub, get_ssl_expiry_date(sub)
                        return sub, {"date": None, "trusted": False, "error": "NO_HTTPS"}

                    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                        future_to_sub = {executor.submit(process_sub, sub): sub for sub in subdomains}
                        for future in concurrent.futures.as_completed(future_to_sub):
                            sub, result = future.result()
                            if result["error"] == "NO_HTTPS": continue
                                
                            if result["date"]:
                                days_left = (result["date"] - now).days
                                if result["trusted"]:
                                    status = "OK"
                                    if days_left <= urg_days:
                                        status = "ACİL"
                                        expiring_entities.append({"domain": f"[SSL] {sub}", "days_left": days_left, "expire_date": result["date"].strftime('%Y-%m-%d')})
                                    elif days_left <= crit_days:
                                        status = "CRITICAL"
                                        expiring_entities.append({"domain": f"[SSL] {sub}", "days_left": days_left, "expire_date": result["date"].strftime('%Y-%m-%d')})
                                    elif days_left <= warn_days:
                                        status = "WARNING"
                                        
                                    temp_results.append({"domain": sub, "root": root_domain, "days_left": days_left, "expire_date": result["date"].strftime('%Y-%m-%d'), "status": status})
                                else:
                                    display_date = f"{result['date'].strftime('%Y-%m-%d')} ({result['error']})"
                                    temp_results.append({"domain": sub, "root": root_domain, "days_left": "GÜVENSİZ", "expire_date": display_date, "status": "ERROR"})
                            else:
                                temp_results.append({"domain": sub, "root": root_domain, "days_left": "Hata", "expire_date": result["error"], "status": "ERROR"})
                
                status_order = {"ACİL": 0, "CRITICAL": 1, "ERROR": 2, "WARNING": 3, "OK": 4}
                temp_results.sort(key=lambda x: (status_order.get(x['status'], 5), x['days_left'] if isinstance(x['days_left'], int) else 9999))
                temp_whois_results.sort(key=lambda x: (status_order.get(x['status'], 5), x['days_left'] if isinstance(x['days_left'], int) else 9999))
                
                scan_results = temp_results
                whois_results = temp_whois_results
                last_scan_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                if expiring_entities: send_notifications(expiring_entities, settings)
        except Exception as e: print(f"[-] Arka plan tarayıcısında hata: {e}")
        finally: is_scanning = False 
        
        scan_trigger.wait(86400)
        scan_trigger.clear()

# --- HTML ŞABLONLARI ---

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Giriş | SSL Guard Enterprise</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body { background-color: #212529; display: flex; align-items: center; justify-content: center; height: 100vh; }</style>
</head>
<body>
    <div class="card shadow-lg border-0" style="width: 100%; max-width: 400px;">
        <div class="card-header bg-primary text-white text-center py-4">
            <h4 class="mb-0 fw-bold">🛡️ SSL Guard Pro</h4>
            <small>Sistem Yöneticisi Girişi</small>
        </div>
        <div class="card-body p-4">
            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                {% for category, message in messages %}
                  <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
              {% endif %}
            {% endwith %}
            <form method="POST">
                <div class="mb-3">
                    <label class="form-label text-muted">Kullanıcı Adı</label>
                    <input type="text" name="username" class="form-control" required autofocus>
                </div>
                <div class="mb-4">
                    <label class="form-label text-muted">Şifre</label>
                    <input type="password" name="password" class="form-control" required>
                </div>
                <button type="submit" class="btn btn-primary w-100 fw-bold py-2">Sisteme Giriş Yap</button>
            </form>
        </div>
    </div>
</body>
</html>
"""

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>SSL Guard | Enterprise Edition (SQL)</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f4f7f6; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;}
        .badge-ACİL { background-color: #8b0000; }
        .badge-CRITICAL { background-color: #d9534f; }
        .badge-WARNING { background-color: #f0ad4e; color: black; }
        .badge-OK { background-color: #5cb85c; }
        .badge-ERROR { background-color: #6c757d; }
        .stat-card { border-left: 5px solid; border-radius: 8px;}
        .stat-total { border-color: #0d6efd; }
        .stat-danger { border-color: #d9534f; }
        .stat-warning { border-color: #f0ad4e; }
        .scan-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(255,255,255,0.85); z-index: 9999; justify-content: center; align-items: center; flex-direction: column; }
    </style>
</head>
<body>

<div id="scanOverlay" class="scan-overlay">
    <div class="spinner-border text-primary" role="status" style="width: 4rem; height: 4rem;"></div>
    <h4 class="mt-4 fw-bold text-dark">Sistem Taraması Devam Ediyor...</h4>
    <p class="text-muted">Güvenlik Motorları (SSL & WHOIS) ve Veritabanı senkronize ediliyor.</p>
</div>

<nav class="navbar navbar-dark bg-dark mb-4 shadow-sm">
    <div class="container d-flex justify-content-between">
        <a class="navbar-brand fw-bold" href="#">🛡️ SSL Guard Enterprise</a>
        <a href="/logout" class="btn btn-outline-light btn-sm">🚪 Çıkış Yap</a>
    </div>
</nav>

<div class="container">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="alert alert-{{ category }} alert-dismissible fade show shadow-sm" role="alert">
            {{ message }}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card stat-card stat-total shadow-sm h-100">
                <div class="card-body">
                    <h6 class="text-muted text-uppercase mb-1">Toplam İzlenen Subdomain</h6>
                    <h2 class="mb-0 fw-bold">{{ stats.total }}</h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stat-card stat-danger shadow-sm h-100">
                <div class="card-body">
                    <h6 class="text-muted text-uppercase mb-1">Acil / Kritik Sertifikalar</h6>
                    <h2 class="mb-0 fw-bold text-danger">{{ stats.critical }}</h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stat-card stat-warning shadow-sm h-100">
                <div class="card-body">
                    <h6 class="text-muted text-uppercase mb-1">Güvensiz / Hatalı (Self-Signed)</h6>
                    <h2 class="mb-0 fw-bold text-warning">{{ stats.errors }}</h2>
                </div>
            </div>
        </div>
    </div>

    <ul class="nav nav-pills mb-4 bg-white p-2 rounded shadow-sm border">
        <li class="nav-item"><button class="nav-link active fw-bold" data-bs-toggle="tab" data-bs-target="#dashboard">📊 SSL Envanteri</button></li>
        <li class="nav-item"><button class="nav-link fw-bold" data-bs-toggle="tab" data-bs-target="#whois">📜 WHOIS (Domain) Durumu</button></li>
        <li class="nav-item"><button class="nav-link fw-bold" data-bs-toggle="tab" data-bs-target="#domains">🌐 Domain Yönetimi</button></li>
        <li class="nav-item"><button class="nav-link fw-bold" data-bs-toggle="tab" data-bs-target="#settings">⚙️ Sistem Ayarları</button></li>
    </ul>

    <div class="tab-content">
        <div class="tab-pane fade show active" id="dashboard">
            <div class="card shadow-sm border-0">
                <div class="card-header bg-white d-flex justify-content-between align-items-center py-3">
                    <h5 class="mb-0 fw-bold text-dark">Sertifika Yaşam Döngüsü</h5>
                    <div>
                        <a href="/export" class="btn btn-success btn-sm me-2">📥 Excel (.xlsx) İndir</a>
                        <form action="/scan" method="POST" class="d-inline"><button type="submit" class="btn btn-primary btn-sm">🔄 Tümünü Tara</button></form>
                    </div>
                </div>
                <div class="card-body p-0">
                    <table class="table table-hover mb-0">
                        <thead class="table-light">
                            <tr>
                                <th>Subdomain</th>
                                <th>Kalan Gün</th>
                                <th>Bitiş / Açıklama</th>
                                <th>Durum</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for root_domain, items in results | groupby('root') %}
                            <tr class="table-active border-top border-2">
                                <td colspan="4" class="fw-bold text-dark py-3">
                                    🌐 {{ root_domain | upper }} 
                                    <span class="badge bg-secondary ms-2 rounded-pill">{{ items|length }} Kayıt</span>
                                </td>
                            </tr>
                                {% for row in items %}
                                <tr class="{% if row.status == 'ERROR' %}table-secondary{% elif row.status == 'ACİL' %}table-danger{% endif %}">
                                    <td class="ps-4"><strong>{{ row.domain }}</strong></td>
                                    <td class="fw-bold">{{ row.days_left }}</td>
                                    <td><small>{{ row.expire_date }}</small></td>
                                    <td><span class="badge badge-{{ row.status }}">{{ row.status }}</span></td>
                                </tr>
                                {% endfor %}
                            {% else %}
                            <tr><td colspan="4" class="text-center py-5">Kurumsal veri bulunamadı. Domain ekleyiniz.</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                <div class="card-footer bg-light"><small class="text-muted">Son Sistem Taraması: {{ last_scan }}</small></div>
            </div>
        </div>

        <div class="tab-pane fade" id="whois">
            <div class="card shadow-sm border-0">
                <div class="card-header bg-white py-3">
                    <h5 class="mb-0 fw-bold text-dark">Kök Alan Adı Tescil Bilgileri (WHOIS)</h5>
                </div>
                <div class="card-body p-0">
                    <table class="table table-hover mb-0">
                        <thead class="table-light">
                            <tr>
                                <th>Kök Alan Adı</th>
                                <th>Kalan Gün</th>
                                <th>Bitiş Tarihi</th>
                                <th>Durum</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for row in whois_results %}
                            <tr class="{% if row.status == 'ERROR' %}table-secondary{% elif row.status == 'ACİL' %}table-danger{% endif %}">
                                <td class="ps-4"><strong>{{ row.domain }}</strong></td>
                                <td class="fw-bold">{{ row.days_left }}</td>
                                <td><small>{{ row.expire_date }}</small></td>
                                <td><span class="badge badge-{{ row.status }}">{{ row.status }}</span></td>
                            </tr>
                            {% else %}
                            <tr><td colspan="4" class="text-center py-5">Domain verisi bekleniyor. Lütfen taramayı başlatın.</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="tab-pane fade" id="domains">
            <div class="row">
                <div class="col-md-4">
                    <div class="card p-4 shadow-sm border-0">
                        <h6 class="fw-bold">Yeni Kurumsal Domain Ekle</h6>
                        <hr>
                        <form action="/add_domain" method="POST">
                            <input type="text" name="domain" class="form-control mb-3" placeholder="Örn: sirket.com.tr" required>
                            <button class="btn btn-dark w-100">Ekle ve Otomatik Tara</button>
                        </form>
                    </div>
                </div>
                <div class="col-md-8">
                    <div class="card shadow-sm p-4 border-0">
                        <h6 class="fw-bold">İzlenen Kök Alan Adları</h6>
                        <hr>
                        <ul class="list-group list-group-flush">
                            {% for d in domains_list %}
                            <li class="list-group-item d-flex justify-content-between align-items-center px-0">{{ d }}
                                <form action="/del_domain/{{ d }}" method="POST" class="m-0"><button class="btn btn-outline-danger btn-sm">Sil</button></form>
                            </li>
                            {% endfor %}
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="tab-pane fade" id="settings">
            <div class="card shadow-sm p-4 border-0">
                <form action="/save_settings" method="POST">
                    <h6 class="fw-bold text-primary mb-3">1. Kademeli Alarm Konfigürasyonu</h6>
                    <div class="row g-3 mb-4">
                        <div class="col-md-4"><label>Erken Uyarı (Gün)</label><input type="number" name="alert_days_warning" class="form-control" value="{{ settings.alert_days_warning }}"></div>
                        <div class="col-md-4"><label>Kritik Seviye (Gün)</label><input type="number" name="alert_days_critical" class="form-control" value="{{ settings.alert_days_critical }}"></div>
                        <div class="col-md-4"><label>Acil Durum (Gün)</label><input type="number" name="alert_days_urgent" class="form-control" value="{{ settings.alert_days_urgent }}"></div>
                    </div>
                    
                    <h6 class="fw-bold text-primary mb-3">2. E-Posta (SMTP) Entegrasyonu</h6>
                    <div class="row g-3 mb-4">
                        <div class="col-md-6"><label>Alıcı Mail Adresi</label><input type="email" name="mail_to" class="form-control" value="{{ settings.mail_to }}"></div>
                        <div class="col-md-4"><label>SMTP Sunucu</label><input type="text" name="smtp_server" class="form-control" value="{{ settings.smtp_server }}"></div>
                        <div class="col-md-2"><label>Port</label><input type="number" name="smtp_port" class="form-control" value="{{ settings.smtp_port }}"></div>
                        <div class="col-md-6"><label>Kullanıcı Adı</label><input type="text" name="smtp_user" class="form-control" value="{{ settings.smtp_user }}"></div>
                        <div class="col-md-6"><label>Şifre / App Password</label><input type="password" name="smtp_pass" class="form-control" value="{{ settings.smtp_pass }}"></div>
                    </div>

                    <h6 class="fw-bold text-primary mb-3">3. Modern Bildirim (Teams / Slack)</h6>
                    <div class="row g-3 mb-4">
                        <div class="col-md-12">
                            <label>Webhook URL (İsteğe Bağlı)</label>
                            <input type="text" name="webhook_url" class="form-control" value="{{ settings.webhook_url }}" placeholder="https://sirket.webhook.office.com/...">
                        </div>
                    </div>

                    <h6 class="fw-bold text-danger mb-3 mt-4">4. Sistem Erişim Güvenliği</h6>
                    <div class="row g-3 mb-4 p-3 bg-light rounded border">
                        <div class="col-md-6">
                            <label class="fw-bold">Yönetici Kullanıcı Adı</label>
                            <input type="text" name="admin_user" class="form-control border-dark" value="{{ settings.admin_user }}" required>
                        </div>
                        <div class="col-md-6">
                            <label class="fw-bold text-danger">Yeni Şifre Belirle</label>
                            <input type="password" name="admin_pass" class="form-control border-danger" placeholder="Değiştirmek istemiyorsanız boş bırakın...">
                        </div>
                    </div>
                    
                    <div class="d-flex justify-content-end gap-2 mt-4 pt-3 border-top">
                        <button type="submit" formaction="/test_mail" formmethod="POST" class="btn btn-outline-info px-4">Test Gönder</button>
                        <button type="submit" class="btn btn-primary px-4">💾 Ayarları Kaydet</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<script>
    const isScanningFromServer = {{ is_scanning | tojson }};
    if (isScanningFromServer) {
        document.getElementById('scanOverlay').style.display = 'flex';
        setInterval(async () => {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                if (!data.is_scanning) location.reload();
            } catch (err) {}
        }, 2000);
    }
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        with get_db() as conn:
            settings = conn.execute("SELECT admin_user, admin_pass FROM settings WHERE id=1").fetchone()
            
        if settings and user == settings['admin_user'] and check_password_hash(settings['admin_pass'], pwd):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            flash('Hatalı kullanıcı adı veya şifre girdiniz!', 'danger')
            
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('Güvenli bir şekilde çıkış yaptınız.', 'success')
    return redirect(url_for('login'))

@app.route("/api/status")
@login_required
def get_status():
    return jsonify({"is_scanning": is_scanning, "last_scan": last_scan_time})

@app.route("/")
@login_required
def index():
    stats = {
        "total": len(scan_results),
        "critical": sum(1 for r in scan_results if r['status'] in ['CRITICAL', 'ACİL']),
        "errors": sum(1 for r in scan_results if r['status'] == 'ERROR')
    }
    return render_template_string(HTML_TEMPLATE, domains_list=get_domains(), results=scan_results, whois_results=whois_results, last_scan=last_scan_time, settings=load_settings(), is_scanning=is_scanning, stats=stats)

@app.route("/add_domain", methods=["POST"])
@login_required
def add_domain():
    new_domain = request.form.get("domain").strip().lower()
    if new_domain:
        with get_db() as conn:
            conn.execute("INSERT OR IGNORE INTO domains (domain_name) VALUES (?)", (new_domain,))
            conn.commit()
        if not is_scanning: scan_trigger.set()
    return redirect(url_for("index"))

@app.route("/del_domain/<domain>", methods=["POST"])
@login_required
def delete_domain(domain):
    global scan_results, whois_results
    with get_db() as conn:
        conn.execute("DELETE FROM domains WHERE domain_name=?", (domain,))
        conn.execute("DELETE FROM cache WHERE domain_name=?", (domain,))
        conn.commit()
        
    scan_results = [r for r in scan_results if r.get("root") != domain]
    whois_results = [r for r in whois_results if r.get("domain") != domain]
    
    if not is_scanning: scan_trigger.set()
        
    flash(f"{domain} veritabanından silindi.", "warning")
    return redirect(url_for("index"))

@app.route("/scan", methods=["POST"])
@login_required
def force_scan():
    if not is_scanning: scan_trigger.set()
    return redirect(url_for("index"))

@app.route("/save_settings", methods=["POST"])
@login_required
def save_settings_route():
    with get_db() as conn:
        conn.execute('''UPDATE settings SET
                        alert_days_warning=?, alert_days_critical=?, alert_days_urgent=?,
                        mail_to=?, smtp_server=?, smtp_port=?, smtp_user=?, smtp_pass=?, webhook_url=?, admin_user=?
                        WHERE id=1''',
                     (request.form.get("alert_days_warning"), request.form.get("alert_days_critical"),
                      request.form.get("alert_days_urgent"), request.form.get("mail_to"),
                      request.form.get("smtp_server"), request.form.get("smtp_port"),
                      request.form.get("smtp_user"), request.form.get("smtp_pass"), 
                      request.form.get("webhook_url"), request.form.get("admin_user")))
        
        new_pass = request.form.get("admin_pass")
        if new_pass and new_pass.strip():
            hashed_pass = generate_password_hash(new_pass.strip())
            conn.execute("UPDATE settings SET admin_pass=? WHERE id=1", (hashed_pass,))
            
        conn.commit()
    flash("Kurumsal ayarlar SQL veritabanına başarıyla kaydedildi.", "success")
    return redirect(url_for("index"))

# --- YENİ: EXCEL EXPORT (ÇİFT SEKMELİ) ---
@app.route("/export")
@login_required
def export_excel():
    wb = openpyxl.Workbook()
    
    # 1. SEKME: SSL ENVANTERİ
    ws_ssl = wb.active
    ws_ssl.title = "SSL Envanteri"
    ws_ssl.append(['Subdomain', 'Kök Domain', 'Kalan Gün', 'Bitiş Tarihi', 'Durum'])
    for row in scan_results:
        ws_ssl.append([row.get('domain'), row.get('root'), row.get('days_left'), row.get('expire_date'), row.get('status')])
        
    # 2. SEKME: WHOIS DURUMU
    ws_whois = wb.create_sheet(title="WHOIS Durumu")
    ws_whois.append(['Kök Alan Adı', 'Kalan Gün', 'Bitiş Tarihi', 'Durum'])
    for row in whois_results:
        ws_whois.append([row.get('domain'), row.get('days_left'), row.get('expire_date'), row.get('status')])

    # Dosyayı hafızaya al
    out = BytesIO()
    wb.save(out)
    out.seek(0)
    
    filename = f"Altyapi_Envanter_Raporu_{datetime.datetime.now().strftime('%Y%m%d')}.xlsx"
    return Response(
        out.getvalue(), 
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@app.route("/test_mail", methods=["POST"])
@login_required
def test_mail_route():
    test_settings = {
        "smtp_server": request.form.get("smtp_server", ""), "smtp_port": request.form.get("smtp_port", 587),
        "smtp_user": request.form.get("smtp_user", ""), "smtp_pass": request.form.get("smtp_pass", ""),
        "mail_to": request.form.get("mail_to", ""), "webhook_url": request.form.get("webhook_url", "")
    }
    
    if test_settings["smtp_server"] and test_settings["smtp_user"]:
        try:
            msg = MIMEMultipart('alternative')
            msg['From'], msg['To'], msg['Subject'] = test_settings['smtp_user'], test_settings['mail_to'], "✅ SSL Guard Enterprise - Test Maili"
            html_body = "<html><body style='padding:20px;'><h2 style='color:#0d6efd;'>Bağlantı Başarılı! 🎉</h2><p>Sistem SMTP altyapısı çalışmaktadır.</p></body></html>"
            msg.attach(MIMEText(html_body, 'html'))
            server = smtplib.SMTP(test_settings['smtp_server'], int(test_settings['smtp_port']), timeout=10)
            server.starttls()
            server.login(test_settings['smtp_user'], test_settings['smtp_pass'])
            server.send_message(msg)
            server.quit()
            flash("✅ Test HTML maili başarıyla gönderildi!", "success")
        except Exception as e: flash(f"❌ Mail Hatası: {e}", "danger")
    
    if test_settings["webhook_url"]:
        try:
            requests.post(test_settings["webhook_url"], json={"text": "✅ SSL Guard Enterprise: Webhook test bağlantısı başarılı."}, timeout=5)
            flash("✅ Webhook bildirimi başarıyla gönderildi.", "success")
        except Exception as e: flash(f"❌ Webhook Hatası: {e}", "danger")
        
    return redirect(url_for("index"))

if __name__ == "__main__":
    threading.Thread(target=background_scanner, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
