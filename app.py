from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from openai import OpenAI
import os, uuid, requests, whois, re, unicodedata, sqlite3
from bs4 import BeautifulSoup
from datetime import datetime
from dotenv import load_dotenv

# ─── Setup ─────────────────────────────────────────────────────────────────────
load_dotenv()
app = Flask(__name__, static_folder='.')
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))
CORS(app, supports_credentials=True)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ─── Database init ─────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect('scamdb.sqlite')
    c = conn.cursor()
    c.execute('''
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        free_checks INTEGER DEFAULT 1,
        is_paid INTEGER DEFAULT 0,
        created_at TIMESTAMP
      )''')
    c.execute('''
      CREATE TABLE IF NOT EXISTS checks (
        domain TEXT PRIMARY KEY,
        risk_score INTEGER,
        full_report TEXT,
        last_checked TIMESTAMP
      )''')
    conn.commit()
    conn.close()

init_db()

# ─── Helpers ──────────────────────────────────────────────────────────────────
def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        return (datetime.now() - cd).days
    except:
        return None

def get_risk_level(score):
    if score >= 85: return "💀 BRO THIS IS 100% SCAM"
    if score >= 65: return "🔥 HIGH RISK SCAM"
    if score >= 40: return "⚠️ SUSPICIOUS"
    return "✅ Likely Legit"

# ─── AA419 Database Check ─────────────────────────────────────────────────────
def check_aa419_database(domain):
    try:
        parts = re.sub(r"https?://", "", domain).split("/")[0].split(".")
        root = ".".join(parts[-2:]) if len(parts)>=2 else domain
        resp = requests.get(
            f"https://db.aa419.org/api.php?type=search&value={root}",
            headers={'User-Agent':'Mozilla/5.0'}, timeout=5)
        data = resp.json()
        if data.get('count',0)>0:
            return {'listed': True, 'entries': data['items'][:3]}
        return {'listed': False}
    except Exception as e:
        return {'listed': False, 'error': str(e)}

# ─── Homograph (Unicode) Scam Detection ────────────────────────────────────────
def detect_character_scams(domain):
    suspicious = {'a':'а','e':'е','o':'о','p':'р','c':'с','y':'у','x':'х','k':'к','m':'м','t':'т'}
    alerts = []
    for ch in domain:
        if ord(ch)>127 and ch in suspicious.values():
            orig = [k for k,v in suspicious.items() if v==ch][0]
            alerts.append(f"Uses '{ch}' (U+{ord(ch):04X}) instead of ASCII '{orig}'")
    return alerts

# ─── Website Scanner ──────────────────────────────────────────────────────────
def scan_website(domain):
    if not domain.startswith(('http://','https://')):
        domain = 'https://' + domain
    resp = requests.get(domain, headers={'User-Agent':'Mozilla/5.0'}, timeout=10)
    html = resp.text
    soup = BeautifulSoup(html, 'html.parser')
    return {
        'ssl': resp.url.startswith('https://'),
        'domain_age': get_domain_age(domain),
        'phishing_count': len(soup.find_all('input', {'type':'password'})),
        'crypto_count': bool(re.search(r'1000% return|guaranteed profit', html, re.I)),
        'unicode_alerts': detect_character_scams(domain)
    }

# ─── AI Analysis ──────────────────────────────────────────────────────────────
def analyze_domain(domain):
    scan = scan_website(domain)
    aa419 = check_aa419_database(domain)

    # Build extra context
    extra = []
    if scan['unicode_alerts']:
        extra.append("🚨 UNICODE HOMOGRAPH SCAM DETECTED:")
        extra.extend(scan['unicode_alerts'])
    if aa419.get('listed'):
        extra.append("🚨 AA419 LISTED SCAM SITE:")
        for e in aa419['entries']:
            extra.append(f"- {e.get('title','no title')} (Added: {e.get('added','unknown')})")

    prompt = f"""
Analyze this website for scams: {domain}
{' '.join(extra)}

Indicators:
- SSL: {'✅' if scan['ssl'] else '❌'}
- Domain Age: {scan['domain_age']} days
- Phishing inputs found: {scan['phishing_count']}
- Crypto red-flag phrases: {"Yes" if scan['crypto_count'] else "No"}

Rules:
1. Unicode scam → RISK ≥95%
2. AA419 listed → RISK ≥90%
3. Age <30 days + crypto → RISK ≥70%
4. Phishing inputs ≥1 → RISK ≥60%

STRICT FORMAT ONLY:
SCAM_RISK: XX% (0-100)
VERDICT: [1-2 sentence summary]
RED_FLAGS:
- bullet
AA419_MATCH: {'Yes' if aa419.get('listed') else 'No'}
"""

    res = client.chat.completions.create(
        model="gpt-4-turbo",
        messages=[{"role":"user","content":prompt}],
        temperature=0.1, max_tokens=400
    )
    report = res.choices[0].message.content
    score = int(re.search(r'SCAM_RISK: (\d+)%', report).group(1))
    return {'risk_score':score,'report':report,'aa419':aa419,'scan':scan}

# ─── Routes ──────────────────────────────────────────────────────────────────
class JSONError(Exception): pass

@app.route('/api/check', methods=['POST'])
def check_domain():
    data = request.get_json()
    dom  = data.get('domain','').strip()
    if not dom: raise JSONError("Domain required")
    sid = request.cookies.get('session_id', str(uuid.uuid4()))

    # manage session
    conn = sqlite3.connect('scamdb.sqlite'); c=conn.cursor()
    c.execute('INSERT OR IGNORE INTO sessions VALUES(?,1,0,datetime("now"))',(sid,))
    c.execute('SELECT free_checks,is_paid FROM sessions WHERE session_id=?',(sid,))
    free,is_paid = c.fetchone()
    if not is_paid and free<=0:
        return jsonify({'status':'locked',
                        'payment_url':'https://akiagi3.gumroad.com/l/bhphh'}),200

    # analyze
    result = analyze_domain(dom)
    if not is_paid:
        c.execute('UPDATE sessions SET free_checks=free_checks-1 WHERE session_id=?',(sid,))
        conn.commit()

    resp = jsonify({
        'status':'unlocked' if is_paid else 'free',
        'risk_score': result['risk_score'],
        'risk_level': get_risk_level(result['risk_score']),
        'full_report': result['report'],
        'aa419_match': result['aa419']['listed']
    })
    resp.set_cookie('session_id',sid,max_age=30*24*60*60,httponly=True,samesite='Lax')
    return resp

@app.errorhandler(JSONError)
def handle_json_error(e):
    return jsonify({'error':str(e)}),400

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_front(path):
    return send_from_directory('.', 'index.html')

@app.route('/api/verify-payment', methods=['POST'])
def verify_payment():
    sid = request.cookies.get('session_id')
    if not sid: return jsonify({'error':'No session'}),400
    conn=sqlite3.connect('scamdb.sqlite'); c=conn.cursor()
    c.execute('UPDATE sessions SET is_paid=1,free_checks=999 WHERE session_id=?',(sid,))
    conn.commit(); conn.close()
    return jsonify({'status':'success'})

# ─── Run ─────────────────────────────────────────────────────────────────────
if __name__=='__main__':
    app.run(host='0.0.0.0',port=int(os.getenv("PORT",5000)),debug=True)
