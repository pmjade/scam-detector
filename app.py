from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from openai import OpenAI
import os
import uuid
import requests
import whois
from bs4 import BeautifulSoup
import re
from datetime import datetime
from dotenv import load_dotenv
import sqlite3
import unicodedata

load_dotenv()
app = Flask(__name__, static_folder='.')
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))
CORS(app, supports_credentials=True)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Database init
def init_db():
    conn = sqlite3.connect('scamdb.sqlite')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            has_used_free_check INTEGER DEFAULT 0,
            checks_remaining INTEGER DEFAULT 1,
            created_at TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS checks (
            domain TEXT PRIMARY KEY,
            risk_score INTEGER,
            full_report TEXT,
            last_checked TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            checks_purchased INTEGER DEFAULT 1,
            checks_used INTEGER DEFAULT 0,
            activated_at TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def detect_character_scams(domain):
    suspicious_pairs = {'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с', 'y': 'у', 'x': 'х', 'k': 'к'}
    detected = []
    for char in domain:
        if ord(char) > 127:
            normalized = unicodedata.normalize('NFKD', char).encode('ascii', 'ignore').decode()
            if normalized and normalized in suspicious_pairs.values():
                original = [k for k, v in suspicious_pairs.items() if v == char][0]
                detected.append(f"Uses '{char}' (U+{ord(char):04X}) instead of '{original}'")
    return detected

def check_aa419_database(domain):
    try:
        root_domain = '.'.join(domain.replace('http://', '').replace('https://', '').split('/')[0].split('.')[-2:])
        response = requests.get(
            f"https://db.aa419.org/api.php?type=search&value={root_domain}",
            headers={'User-Agent': 'Mozilla/5.0'},
            timeout=5
        )
        if 'application/json' not in response.headers.get('Content-Type', ''):
            return {'error': 'Invalid AA419 response format'}
        data = response.json()
        if data.get('count', 0) > 0:
            return {
                'listed': True,
                'entries': data['items'][:3],
                'source': 'AA419 Database'
            }
        return {'listed': False}
    except Exception as e:
        return {'error': f"AA419 check failed: {str(e)}"}

def get_domain_age(domain):
    try:
        clean = domain.replace('http://', '').replace('https://', '').split('/')[0]
        w = whois.whois(clean)
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        return (datetime.now() - creation_date).days if creation_date else None
    except:
        return None

def scan_website(domain):
    try:
        char_alerts = detect_character_scams(domain)
        if not domain.startswith(('http://', 'https://')):
            domain = f'https://{domain}'
        response = requests.get(domain, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        return {
            'ssl': response.url.startswith('https://'),
            'domain_age': get_domain_age(domain),
            'phishing': {
                'fake_login': bool(soup.find('input', {'type': 'password'})),
                'brand_logos': len(soup.find_all('img', {'alt': re.compile('login|sign in|bank|paypal', re.I)})) > 0
            },
            'crypto': {
                'unrealistic_returns': bool(re.search(r'1000% return|guaranteed profit', response.text, re.I)),
                'token_pressure': bool(re.search(r'limited offer|almost sold out', response.text, re.I))
            },
            'unicode_scam': char_alerts if char_alerts else None
        }
    except Exception as e:
        return {'error': str(e)}

def analyze_domain(domain):
    try:
        scan = scan_website(domain)
        if 'error' in scan:
            return {'error': scan['error']}
        aa419_check = check_aa419_database(domain)

        aa419_info = ""
        if aa419_check.get('listed'):
            aa419_info = "\n🚨 AA419 LISTED SCAM SITE:\n"
            for entry in aa419_check.get('entries', []):
                aa419_info += f"- {entry.get('title', 'No title')} (Added: {entry.get('added', 'Unknown')})\n"

        prompt = f"""
Analyze this website for scams: {domain}

Technical Indicators:
- SSL: {'✅' if scan['ssl'] else '❌'}
- Domain Age: {scan.get('domain_age', 'Unknown')} days
- Phishing Signs: {sum(scan['phishing'].values())}/{len(scan['phishing'])}
- Crypto Red Flags: {sum(scan['crypto'].values())}/{len(scan['crypto'])}
{aa419_info}

Critical Rules:
1. If Unicode scam detected → RISK ≥95%
2. If AA419 listed → RISK ≥90%
3. If <30 days old + crypto → RISK ≥70%
4. If phishing signs ≥2 → RISK ≥60%

Response Format (STRICT):
SCAM_RISK: XX% (0-100)
VERDICT: [1-2 sentence summary]
RED_FLAGS:
- [3-5 specific issues]
"""
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=600
        )
        report = response.choices[0].message.content
        risk_score = int(re.search(r'SCAM_RISK: (\d+)%', report).group(1))
        return {
            'risk_score': risk_score,
            'full_report': report,
            'technical': scan,
            'aa419_check': aa419_check,
            'unicode_alerts': scan.get('unicode_scam')
        }
    except Exception as e:
        return {'error': f"Analysis failed: {str(e)}"}

@app.route('/api/verify-license', methods=['POST'])
def verify_license():
    conn = None
    try:
        data = request.get_json(force=True)
        license_key = data.get('license_key', '').strip()
        session_id = request.cookies.get('session_id')
        if not license_key or not session_id:
            return jsonify({"error": "License key and session required"}), 400

        gumroad_response = requests.post(
            "https://api.gumroad.com/v2/licenses/verify",
            data={
                "product_permalink": "bhphh",
                "license_key": license_key
            },
            timeout=10,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        if 'application/json' not in gumroad_response.headers.get('Content-Type', ''):
            return jsonify({"error": "Gumroad API returned HTML instead of JSON"}), 500

        gumroad_data = gumroad_response.json()
        if not gumroad_data.get("success"):
            return jsonify({"error": gumroad_data.get("message", "Invalid license key")}), 400

        conn = sqlite3.connect('scamdb.sqlite')
        cursor = conn.cursor()
        cursor.execute('SELECT checks_used FROM licenses WHERE license_key = ?', (license_key,))
        existing = cursor.fetchone()
        if existing and existing[0] >= 1:
            return jsonify({"error": "This license has already been used"}), 400

        cursor.execute('''
            INSERT OR IGNORE INTO licenses (license_key, checks_purchased, activated_at)
            VALUES (?, 1, datetime("now"))
        ''', (license_key,))
        cursor.execute('''
            UPDATE sessions SET checks_remaining = checks_remaining + 1 WHERE session_id = ?
        ''', (session_id,))
        cursor.execute('''
            UPDATE licenses SET checks_used = checks_used + 1 WHERE license_key = ?
        ''', (license_key,))
        conn.commit()
        return jsonify({"status": "success", "message": "License activated", "checks_added": 1})

    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500
    finally:
        if conn: conn.close()

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
