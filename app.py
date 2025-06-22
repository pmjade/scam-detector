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

# Setup
load_dotenv()
app = Flask(__name__, static_folder='.')
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))
CORS(app, supports_credentials=True)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Database setup
def init_db():
    conn = sqlite3.connect('scamdb.sqlite')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            free_checks INTEGER DEFAULT 1,
            is_paid INTEGER DEFAULT 0,
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
    conn.commit()
    conn.close()

init_db()

def get_risk_level(score):
    if score >= 85: return "💀 BRO THIS IS 100% SCAM"
    elif score >= 65: return "🔥 HIGH RISK SCAM"
    elif score >= 40: return "⚠️ SUSPICIOUS"
    return "✅ Likely Legit"

def scan_website(domain):
    try:
        if not domain.startswith(('http://', 'https://')):
            domain = f'https://{domain}'
        
        response = requests.get(
            domain,
            headers={'User-Agent': 'Mozilla/5.0'},
            timeout=10,
            allow_redirects=True
        )
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        return {
            'ssl': response.url.startswith('https://'),
            'domain_age': get_domain_age(domain),
            'phishing': {
                'fake_login': len(soup.find_all('input', {'type': 'password'})) > 0,
                'brand_logos': len(soup.find_all('img', {'alt': re.compile('login|sign in|bank|paypal', re.I)})) > 0
            },
            'crypto': {
                'unrealistic_returns': bool(re.search(r'1000% return|guaranteed profit', html, re.I)),
                'token_pressure': bool(re.search(r'limited offer|almost sold out', html, re.I))
            }
        }
    except Exception as e:
        return {'error': str(e)}

def analyze_domain(domain):
    try:
        scan = scan_website(domain)
        if 'error' in scan:
            return {'error': scan['error']}

        prompt = f"""
Analyze this website for scams: {domain}

Technical Indicators:
- SSL: {'✅' if scan['ssl'] else '❌'}
- Domain Age: {scan.get('domain_age', 'Unknown')} days
- Phishing Signs: {sum(scan['phishing'].values())}/{len(scan['phishing'])}
- Crypto Red Flags: {sum(scan['crypto'].values())}/{len(scan['crypto'])}

Provide analysis in EXACT format:
SCAM_RISK: XX% (0-100)
VERDICT: [1-2 sentence summary]
RED_FLAGS:
- [3 specific issues]
"""

        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=500
        )
        
        report = response.choices[0].message.content
        risk_score = int(re.search(r'SCAM_RISK: (\d+)%', report).group(1))
        
        return {
            'risk_score': risk_score,
            'full_report': report,
            'technical': scan
        }
    except Exception as e:
        return {'error': f"Analysis failed: {str(e)}"}

@app.route('/api/check', methods=['POST'])
def check_domain():
    try:
        domain = request.json.get('domain', '').strip()
        if not domain:
            return jsonify({'error': 'Domain required'}), 400

        session_id = request.cookies.get('session_id', str(uuid.uuid4()))
        conn = sqlite3.connect('scamdb.sqlite')
        cursor = conn.cursor()

        # Session handling
        cursor.execute('INSERT OR IGNORE INTO sessions VALUES (?, 1, 0, datetime("now"))', (session_id,))
        cursor.execute('SELECT free_checks, is_paid FROM sessions WHERE session_id = ?', (session_id,))
        checks_left, is_paid = cursor.fetchone()

        if not is_paid and checks_left <= 0:
            return jsonify({
                'status': 'locked',
                'payment_url': 'https://akiagi3.gumroad.com/l/bhphh'
            })

        # Domain analysis
        analysis = analyze_domain(domain)
        if 'error' in analysis:
            return jsonify({'error': analysis['error']}), 500

        if not is_paid:
            cursor.execute('UPDATE sessions SET free_checks = free_checks - 1 WHERE session_id = ?', (session_id,))
            conn.commit()

        response = jsonify({
            'status': 'unlocked' if is_paid else 'free',
            'risk_score': analysis['risk_score'],
            'risk_level': get_risk_level(analysis['risk_score']),
            'full_report': analysis['full_report'],
            'technical': analysis['technical']
        })
        
        response.set_cookie(
            'session_id',
            value=session_id,
            max_age=30*24*60*60,
            httponly=True,
            samesite='Lax',
            secure=True
        )
        return response

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ... [keep other routes same] ...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
