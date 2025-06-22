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

def detect_character_scams(domain):
    """Detect homograph attacks using Unicode lookalike characters"""
    suspicious_pairs = {
        'a': 'а',  # Cyrillic 'а'
        'e': 'е',  # Cyrillic 'е'
        'o': 'о',  # Cyrillic 'о'
        'p': 'р',  # Cyrillic 'р'
        'c': 'с',  # Cyrillic 'с'
        'y': 'у',  # Cyrillic 'у'
        'x': 'х',  # Cyrillic 'х'
    }
    
    detected = []
    for char in domain:
        if ord(char) > 127:  # Non-ASCII character
            normalized = unicodedata.normalize('NFKD', char).encode('ascii', 'ignore').decode()
            if normalized and normalized in suspicious_pairs.values():
                original = [k for k, v in suspicious_pairs.items() if v == char][0]
                detected.append(f"Uses '{char}' (U+{ord(char):04X}) instead of '{original}'")
    return detected

def check_aa419_database(domain):
    """Check if domain is listed in AA419 fake sites database"""
    try:
        domain_parts = domain.replace('https://', '').replace('http://', '').split('/')[0].split('.')
        root_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) > 1 else domain
        
        response = requests.get(
            f"https://db.aa419.org/api.php?type=search&value={root_domain}",
            headers={'User-Agent': 'Mozilla/5.0'},
            timeout=5
        )
        
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

def get_risk_level(score):
    if score >= 85: return "💀 BRO THIS IS 100% SCAM"
    elif score >= 65: return "🔥 HIGH RISK SCAM"
    elif score >= 40: return "⚠️ SUSPICIOUS"
    return "✅ Likely Legit"

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        return (datetime.now() - creation_date).days if creation_date else None
    except:
        return None

def scan_website(domain):
    try:
        char_alerts = detect_character_scams(domain)
        
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
            },
            'unicode_scam': char_alerts if char_alerts else None
        }
    except Exception as e:
        return {'error': str(e)}

def analyze_domain(domain):
    try:
        scan = scan_website(domain)
        aa419_check = check_aa419_database(domain)
        
        if 'error' in scan:
            return {'error': scan['error']}
        
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
{aa419_info if aa419_info else ""}

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

@app.route('/api/check', methods=['POST'])
def check_domain():
    try:
        domain = request.json.get('domain', '').strip()
        if not domain:
            return jsonify({'error': 'Domain required'}), 400

        session_id = request.cookies.get('session_id', str(uuid.uuid4()))
        conn = sqlite3.connect('scamdb.sqlite')
        cursor = conn.cursor()

        cursor.execute('INSERT OR IGNORE INTO sessions VALUES (?, 1, 0, datetime("now"))', (session_id,))
        cursor.execute('SELECT free_checks, is_paid FROM sessions WHERE session_id = ?', (session_id,))
        checks_left, is_paid = cursor.fetchone()

        if not is_paid and checks_left <= 0:
            return jsonify({
                'status': 'locked',
                'payment_url': 'https://akiagi3.gumroad.com/l/bhphh'
            })

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
            'technical': analysis['technical'],
            'aa419_check': analysis.get('aa419_check', {}).get('listed', False),
            'unicode_alerts': analysis.get('unicode_alerts')
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

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/api/verify-payment', methods=['POST'])
def verify_payment():
    try:
        session_id = request.cookies.get('session_id')
        if not session_id:
            return jsonify({"error": "No session"}), 400
        
        conn = sqlite3.connect('scamdb.sqlite')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE sessions SET 
            is_paid = 1,
            free_checks = 999 
            WHERE session_id = ?
        ''', (session_id,))
        conn.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
