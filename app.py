from flask import Flask, request, jsonify, send_from_directory, make_response
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
    # This table now stores user-specific data including checks_remaining and expected_license_key
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            checks_remaining INTEGER DEFAULT 1, -- Each new user gets 1 free check
            expected_license_key TEXT,         -- For the Deepseek license flow
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def detect_character_scams(domain):
    """Detect homograph attacks using Unicode lookalike characters"""
    suspicious_pairs = {
        'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р',
        'c': 'с', 'y': 'у', 'x': 'х', 'k': 'к'
    }
    
    detected = []
    for char in domain:
        if ord(char) > 127:
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
    conn = None
    try:
        domain = request.json.get('domain', '').strip()
        if not domain:
            return jsonify({'error': 'Domain required'}), 400

        user_id = request.cookies.get('user_id')
        conn = sqlite3.connect('scamdb.sqlite')
        cursor = conn.cursor()

        # Get or create user
        if not user_id:
            user_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO users (user_id, checks_remaining, created_at, last_activity) 
                VALUES (?, 1, datetime("now"), datetime("now"))
            ''', (user_id,))
            conn.commit()
            checks_remaining = 1 # New user, so 1 check initially
        else:
            cursor.execute('SELECT checks_remaining FROM users WHERE user_id = ?', (user_id,))
            user_data = cursor.fetchone()
            if not user_data: # User ID from cookie but not in DB (e.g., DB reset)
                user_id = str(uuid.uuid4()) # Generate new ID
                cursor.execute('''
                    INSERT INTO users (user_id, checks_remaining, created_at, last_activity) 
                    VALUES (?, 1, datetime("now"), datetime("now"))
                ''', (user_id,))
                conn.commit()
                checks_remaining = 1
            else:
                checks_remaining = user_data[0]

        # Check if user has checks remaining
        if checks_remaining <= 0:
            resp = make_response(jsonify({
                'error': 'No checks remaining',
                'message': 'Please purchase a license key for additional checks ($2 per check)'
            }), 402)
            resp.set_cookie('user_id', user_id, max_age=365*24*60*60, httponly=True, samesite='Lax', secure=True)
            return resp

        analysis = analyze_domain(domain)
        if 'error' in analysis:
            resp = make_response(jsonify({'error': analysis['error']}), 500)
            resp.set_cookie('user_id', user_id, max_age=365*24*60*60, httponly=True, samesite='Lax', secure=True)
            return resp

        # Update checks remaining for the user
        new_checks = checks_remaining - 1
        cursor.execute('''
            UPDATE users 
            SET checks_remaining = ?, last_activity = datetime("now")
            WHERE user_id = ?
        ''', (new_checks, user_id))
        conn.commit()

        resp = make_response(jsonify({
            'status': 'free' if new_checks > 0 else 'locked',
            'risk_score': analysis['risk_score'],
            'risk_level': get_risk_level(analysis['risk_score']),
            'full_report': analysis['full_report'],
            'technical': analysis['technical'],
            'aa419_check': analysis.get('aa419_check', {}).get('listed', False),
            'unicode_alerts': analysis.get('unicode_alerts'),
            'checks_remaining': new_checks # Send checks_remaining back to client
        }))
        
        resp.set_cookie(
            'user_id',
            value=user_id,
            max_age=365*24*60*60, # 1 year
            httponly=True,
            samesite='Lax',
            secure=True
        )
        return resp

    except Exception as e:
        app.logger.error(f"Error in check_domain: {str(e)}") # Log the error for debugging
        return jsonify({'error': f"An internal server error occurred: {str(e)}"}), 500
    finally:
        if conn: conn.close()

@app.route('/api/generate-license', methods=['POST'])
def generate_license():
    conn = None
    try:
        user_id = request.cookies.get('user_id')
        conn = sqlite3.connect('scamdb.sqlite')
        cursor = conn.cursor()

        # Get or create user
        if not user_id:
            user_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO users (user_id, checks_remaining, created_at, last_activity) 
                VALUES (?, 1, datetime("now"), datetime("now"))
            ''', (user_id,))
            conn.commit()
        else:
            cursor.execute('SELECT 1 FROM users WHERE user_id = ?', (user_id,))
            if not cursor.fetchone(): # User ID from cookie but not in DB
                user_id = str(uuid.uuid4())
                cursor.execute('''
                    INSERT INTO users (user_id, checks_remaining, created_at, last_activity) 
                    VALUES (?, 1, datetime("now"), datetime("now"))
                ''', (user_id,))
                conn.commit()
        
        license_key = f"VF-{uuid.uuid4().hex[:8].upper()}"  # Generate unique key
        
        # Store the expected license key for this user
        cursor.execute('''
            UPDATE users 
            SET expected_license_key = ?, last_activity = datetime("now")
            WHERE user_id = ?
        ''', (license_key, user_id))
        conn.commit()
        
        resp = make_response(jsonify({
            "license_key": license_key,
            "checkout_url": f"https://akiagi3.gumroad.com/l/bhphh?license_key={license_key}"
        }))
        resp.set_cookie(
            'user_id',
            value=user_id,
            max_age=365*24*60*60, # 1 year
            httponly=True,
            samesite='Lax',
            secure=True
        )
        return resp
    except Exception as e:
        app.logger.error(f"Error in generate_license: {str(e)}")
        return jsonify({"error": f"An internal server error occurred: {str(e)}"}), 500
    finally:
        if conn: conn.close()

@app.route('/api/verify-license', methods=['POST'])
def verify_license():
    conn = None
    try:
        data = request.json
        license_key = data.get('license_key', '').strip().upper()
        user_id = request.cookies.get('user_id')
        
        if not license_key:
            return jsonify({"error": "License key required"}), 400
            
        if not user_id:
            # This case should ideally not happen if user_id is properly persisted,
            # but acts as a fallback/guard.
            return jsonify({"error": "User session expired or invalid. Please check a domain first."}), 400
            
        conn = sqlite3.connect('scamdb.sqlite')
        cursor = conn.cursor()
        
        # Verify key matches what we expected for this user, and that it's present
        cursor.execute('''
            SELECT checks_remaining FROM users 
            WHERE user_id = ? AND expected_license_key = ?
        ''', (user_id, license_key))
        
        user_data = cursor.fetchone()
        
        if not user_data:
            return jsonify({"error": "Invalid license key for this user. Please ensure you purchased this key from the link we provided and it's the correct one."}), 400
        
        # Increment checks_remaining for the user and clear the expected_license_key
        # The Deepseek prompt implies 1 check is granted per successful verification
        new_checks_remaining = user_data[0] + 1 
        cursor.execute('''
            UPDATE users 
            SET checks_remaining = ?,
                expected_license_key = NULL,
                last_activity = datetime("now")
            WHERE user_id = ?
        ''', (new_checks_remaining, user_id,))
        conn.commit()
        
        resp = make_response(jsonify({
            "status": "success",
            "message": f"License activated! You've received 1 additional check. You now have {new_checks_remaining} checks."
        }))
        resp.set_cookie(
            'user_id',
            value=user_id,
            max_age=365*24*60*60, # 1 year
            httponly=True,
            samesite='Lax',
            secure=True
        )
        return resp
        
    except Exception as e:
        app.logger.error(f"Error in verify_license: {str(e)}")
        return jsonify({"error": f"An internal server error occurred: {str(e)}"}), 500
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
