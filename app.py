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

# Detection modules
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
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        return (datetime.now() - creation_date).days if creation_date else None
    except:
        return None

def scan_website(domain):
    try:
        response = requests.get(
            f"https://{domain}",
            headers={'User-Agent': 'Mozilla/5.0'},
            timeout=10
        )
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

def analyze_domain(domain):
    conn = sqlite3.connect('scamdb.sqlite')
    try:
        cursor = conn.cursor()
        
        # Check cache
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

        # Generate AI report
        prompt = f"""
Analyze this website: {domain}

Technical Scan:
- SSL: {'✅' if scan_results['ssl'] else '❌'}
- Age: {scan_results.get('domain_age', 'Unknown')} days
- Phishing Signs: {sum(scan_results['phishing'].values())}/4
- Celebrity Scams: {sum(scan_results['celebrity'].values())}/3  
- Crypto Red Flags: {sum(scan_results['crypto'].values())}/4

Required Format:
SCAM_PROBABILITY: XX% (0-100)
RISK_LEVEL: [Low/Medium/High/💀 DEATH SCAM]
VERDICT: [1-2 sentence summary]
PHISHING_RISK: [Low/Medium/High]
CELEBRITY_SCAM: [Yes/Suspected/No]
CRYPTO_RISK: [Low/Medium/High]
RED_FLAGS:
- [3-5 critical issues]
"""

        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=600
        )
        
        report = response.choices[0].message.content.strip()
        probability = int(re.search(r'SCAM_PROBABILITY: (\d+)%', report).group(1))

        # Cache results
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

# Routes
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/api/check', methods=['POST'])
def check_domain():
    domain = request.json.get('domain', '').strip()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    session_id = request.cookies.get('session_id', str(uuid.uuid4()))
    conn = sqlite3.connect('scamdb.sqlite')
    
    try:
        cursor = conn.cursor()
        
        # Get or create session
        cursor.execute('''
            INSERT OR IGNORE INTO sessions 
            VALUES (?, 1, 0, datetime('now'))
        ''', (session_id,))
        
        cursor.execute('''
            SELECT free_checks, is_paid FROM sessions 
            WHERE session_id = ?
        ''', (session_id,))
        free_checks, is_paid = cursor.fetchone()

        # Check access
        if is_paid or free_checks > 0:
            analysis = analyze_domain(domain)
            if 'error' in analysis:
                return jsonify({"error": analysis['error']}), 500
            
            if not is_paid:
                cursor.execute('''
                    UPDATE sessions SET 
                    free_checks = free_checks - 1 
                    WHERE session_id = ?
                ''', (session_id,))
                conn.commit()

            # Safely get risk score
            try:
                risk_score = analysis['probability']
            except KeyError:
                risk_score = 0

            if risk_score >= 85:
                level = "💀 BRO THIS IS 100% SCAM"
            elif risk_score >= 65:
                level = "🔥 HIGH RISK SCAM"
            elif risk_score >= 40:
                level = "⚠️ SUSPICIOUS"
            else:
                level = "✅ Likely Legit"

            response = jsonify({
                "status": "unlocked" if is_paid else "free",
                "risk_score": risk_score,
                "risk_level": level,
                "full_report": analysis.get('full_report', 'N/A'),
                "technical_findings": analysis.get('scan_results', {})
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
        
        return jsonify({
            "status": "locked",
            "payment_url": "https://akiagi3.gumroad.com/l/bhphh"
        })
    finally:
        conn.close()

@app.route('/api/verify-payment', methods=['POST'])
def verify_payment():
    session_id = request.cookies.get('session_id')
    if not session_id:
        return jsonify({"error": "No session"}), 400
    
    conn = sqlite3.connect('scamdb.sqlite')
    try:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE sessions SET 
            is_paid = 1,
            free_checks = 999 
            WHERE session_id = ?
        ''', (session_id,))
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))

