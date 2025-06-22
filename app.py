from flask import Flask, request, jsonify
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

# Setup
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))
CORS(app, supports_credentials=True)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# DB Setup
def init_db():
    conn = sqlite3.connect('scamdb.sqlite')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS checks (
            domain TEXT PRIMARY KEY,
            risk_score INTEGER,
            full_report TEXT,
            last_checked TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ==========================
# DETECTION MODULES
# ==========================

def detect_phishing(html):
    soup = BeautifulSoup(html, 'html.parser')
    return {
        'fake_login': len(soup.find_all('input', {'type': 'password'})) > 0,
        'brand_logos': len(soup.find_all('img', {'alt': re.compile('login|sign in|bank|paypal', re.I)})) > 0,
        'urgency_text': bool(re.search(r'urgent|immediately|action required', html, re.I)),
        'hidden_redirects': len(soup.find_all('meta', {'http-equiv': 'refresh'})) > 0
    }

def detect_celebrity_scams(html):
    soup = BeautifulSoup(html, 'html.parser')
    return {
        'fake_testimonials': len(soup.find_all(class_=re.compile('testimonial|endorsement', re.I))) > 0,
        'stock_photos': len(soup.find_all('img', {'src': re.compile('stock|shutterstock', re.I)})) > 0,
        'common_names': bool(re.search(r'elon musk|mr beast|tate|oprah|bezos', html, re.I))
    }

def detect_crypto_scams(html):
    soup = BeautifulSoup(html, 'html.parser')
    return {
        'unrealistic_returns': bool(re.search(r'1000% return|guaranteed profit', html, re.I)),
        'fake_team': len(soup.find_all(class_=re.compile('team|advisor', re.I))) > 3,
        'no_whitepaper': not bool(re.search(r'whitepaper|technical', html, re.I)),
        'token_pressure': bool(re.search(r'limited offer|almost sold out', html, re.I))
    }

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return (datetime.now() - creation_date).days
    except:
        return None

def scan_website(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=10, headers={
            'User-Agent': 'Mozilla/5.0'
        })
        html = response.text

        return {
            'phishing': detect_phishing(html),
            'celebrity': detect_celebrity_scams(html),
            'crypto': detect_crypto_scams(html),
            'ssl': response.url.startswith('https://'),
            'domain_age': get_domain_age(domain)
        }
    except Exception as e:
        return {'error': str(e)}

def format_scan_results(scan):
    out = []

    if any(scan['phishing'].values()):
        out.append("🕵️ PHISHING SIGNS:")
        for k, v in scan['phishing'].items():
            if v: out.append(f"- {k.replace('_', ' ').title()}")

    if any(scan['celebrity'].values()):
        out.append("\n🌟 CELEBRITY SCAM SIGNS:")
        for k, v in scan['celebrity'].items():
            if v: out.append(f"- {k.replace('_', ' ').title()}")

    if any(scan['crypto'].values()):
        out.append("\n₿ CRYPTO SCAM SIGNS:")
        for k, v in scan['crypto'].items():
            if v: out.append(f"- {k.replace('_', ' ').title()}")

    return '\n'.join(out)

# ==========================
# AI ANALYSIS
# ==========================

def analyze_domain(domain):
    conn = sqlite3.connect('scamdb.sqlite')
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM checks WHERE domain = ?', (domain,))
        cached = cursor.fetchone()
        if cached and (datetime.now() - datetime.strptime(cached[3], '%Y-%m-%d %H:%M:%S')).days < 1:
            return {
                'probability': cached[1],
                'full_report': cached[2],
                'cached': True
            }

        scan_results = scan_website(domain)
        if 'error' in scan_results:
            return {'error': scan_results['error']}

        prompt = f"""
WEBSITE ANALYSIS FOR: {domain}

SSL Secure: {'✅' if scan_results['ssl'] else '❌'}
Domain Age: {scan_results.get('domain_age', 'Unknown')} days

Phishing: {sum(scan_results['phishing'].values())}/4 triggered
Celebrity Scam: {sum(scan_results['celebrity'].values())}/3 triggered
Crypto Scam: {sum(scan_results['crypto'].values())}/4 triggered

Details:
{format_scan_results(scan_results)}

Return in format:
SCAM_PROBABILITY: XX%
RISK_LEVEL: [Low/Medium/High/💀 DEATH SCAM]
VERDICT: [Brief summary]
PHISHING_RISK: [Low/Medium/High]
CELEBRITY_SCAM: [Yes/Suspected/No]
CRYPTO_RISK: [Low/Medium/High]
RED_FLAGS:
- bullet
- bullet
- bullet
"""

        res = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=600
        )
        report = res.choices[0].message.content.strip()
        probability = int(re.search(r'SCAM_PROBABILITY: (\d+)%', report).group(1))

        cursor.execute('''
            INSERT OR REPLACE INTO checks 
            VALUES (?, ?, ?, datetime('now'))
        ''', (domain, probability, report))
        conn.commit()

        return {
            'probability': probability,
            'full_report': report,
            'scan_results': scan_results
        }
    finally:
        conn.close()

# ==========================
# ROUTES
# ==========================

@app.route('/check', methods=['POST'])
def check_domain():
    domain = request.json.get('domain', '').strip()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    session_id = request.cookies.get('session_id', str(uuid.uuid4()))

    result = analyze_domain(domain)
    if 'error' in result:
        return jsonify({"error": result['error']}), 500

    risk_score = result['probability']
    if risk_score >= 80:
        level = "💀 BRO THIS IS 100% SCAM"
    elif risk_score >= 60:
        level = "🔥 HIGH RISK SCAM"
    elif risk_score >= 30:
        level = "⚠️ MEDIUM RISK"
    else:
        level = "✅ Likely Legit"

    response = jsonify({
        "risk_score": risk_score,
        "risk_level": level,
        "full_report": result['full_report'],
        "technical_findings": result.get('scan_results', {})
    })

    response.set_cookie(
        'session_id',
        value=session_id,
        max_age=30*24*60*60,
        httponly=True,
        samesite='Lax'
    )
    return response
