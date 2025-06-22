from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from openai import OpenAI
import os, uuid, requests, whois, sqlite3, unicodedata, re
from bs4 import BeautifulSoup
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__, static_folder='.')
app.secret_key = os.getenv("FLASK_SECRET_KEY") or os.urandom(24)
CORS(app, supports_credentials=True)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# DB init
def init_db():
    conn = sqlite3.connect('scamdb.sqlite')
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        free_checks INTEGER DEFAULT 1,
        is_paid INTEGER DEFAULT 0,
        created_at TIMESTAMP)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS checks (
        domain TEXT PRIMARY KEY,
        risk_score INTEGER,
        full_report TEXT,
        last_checked TIMESTAMP)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS licenses (
        license_key TEXT PRIMARY KEY,
        is_used INTEGER DEFAULT 0,
        activated_at TIMESTAMP)''')
    conn.commit()
    conn.close()
init_db()

# Helpers
def get_or_create_session():
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    sid = session['session_id']
    conn = sqlite3.connect('scamdb.sqlite')
    cur = conn.cursor()
    cur.execute('SELECT * FROM sessions WHERE session_id=?', (sid,))
    if not cur.fetchone():
        cur.execute('INSERT INTO sessions VALUES (?, 1, 0, ?)', (sid, datetime.now()))
        conn.commit()
    conn.close()
    return sid

def get_risk_level(score):
    if score >= 85: return "💀 BRO THIS IS 100% SCAM"
    if score >= 65: return "🔥 HIGH RISK SCAM"
    if score >= 40: return "⚠️ SUSPICIOUS"
    return "✅ Likely Legit"

# (Include your existing detect_character_scams, check_aa419_database,
# scan_website, analyze_domain here unchanged)

@app.route('/api/check', methods=['POST'])
def check_domain():
    domain = request.json.get('domain','').strip()
    if not domain: return jsonify({'error':'Domain required'}),400

    sid = get_or_create_session()
    conn = sqlite3.connect('scamdb.sqlite')
    cur = conn.cursor()
    cur.execute('SELECT free_checks, is_paid FROM sessions WHERE session_id=?', (sid,))
    free_checks, is_paid = cur.fetchone()

    if free_checks <= 0 and not is_paid:
        conn.close()
        return jsonify({
            'status':'locked',
            'message':'Free check used. Unlock with license key.'
        }), 402

    # reuse cached or perform analysis
    cur.execute('SELECT risk_score, full_report FROM checks WHERE domain=?', (domain,))
    cached = cur.fetchone()
    if cached:
        risk, report = cached
    else:
        res = analyze_domain(domain)
        if 'error' in res:
            conn.close(); return jsonify({'error':res['error']}),500
        risk, report = res['risk_score'], res['full_report']
        cur.execute('REPLACE INTO checks VALUES (?, ?, ?, ?)', (domain, risk, report, datetime.now()))
        conn.commit()

    if free_checks > 0:
        cur.execute('UPDATE sessions SET free_checks=free_checks-1 WHERE session_id=?', (sid,))
        conn.commit()
        conn.close()
        return jsonify({
            'status':'free',
            'risk_score':risk,
            'risk_level':get_risk_level(risk),
            'full_report':report
        })

    if is_paid:
        # consumes paid once
        cur.execute('UPDATE sessions SET is_paid=0 WHERE session_id=?',(sid,))
        conn.commit()
        conn.close()
        return jsonify({
            'status':'paid',
            'risk_score':risk,
            'risk_level':get_risk_level(risk),
            'full_report':report
        })

    conn.close()
    return jsonify({'status':'locked'}),402

@app.route('/api/verify-license', methods=['POST'])
def verify_license():
    key = request.json.get('license_key','').strip().upper()
    if not key: return jsonify({'error':'License key required'}),400
    sid = get_or_create_session()
    conn = sqlite3.connect('scamdb.sqlite')
    cur = conn.cursor()
    cur.execute('SELECT is_used FROM licenses WHERE license_key=?',(key,))
    row = cur.fetchone()
    if not row: conn.close(); return jsonify({'error':'Invalid key'}),400
    if row[0]: conn.close(); return jsonify({'error':'Key already used'}),403
    cur.execute('UPDATE licenses SET is_used=1, activated_at=? WHERE license_key=?',(datetime.now(),key))
    cur.execute('UPDATE sessions SET is_paid=1 WHERE session_id=?',(sid,))
    conn.commit(); conn.close()
    return jsonify({'status':'success'})

@app.route('/', defaults={'path':''})
@app.route('/<path:path>')
def serve(path): return send_from_directory('.', 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=int(os.getenv("PORT",5000)))
