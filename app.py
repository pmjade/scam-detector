from flask import Flask, request, jsonify, send_from_directory, make_response, redirect
from flask_cors import CORS
from openai import OpenAI
import os
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv
import requests
import pickle
import atexit

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", str(uuid.uuid4()))
CORS(app, supports_credentials=True)

# OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Sessions and cache
sessions = {}
analysis_cache = {}

# Load saved sessions
try:
    with open("sessions.pkl", "rb") as f:
        sessions.update(pickle.load(f))
except:
    pass

# Save sessions on exit
def save_sessions():
    with open("sessions.pkl", "wb") as f:
        pickle.dump(sessions, f)

atexit.register(save_sessions)

# Fetch Reddit discussions
def get_reddit_sentiment(domain):
    try:
        url = f"https://www.reddit.com/search.json?q={domain}&sort=new"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers)
        posts = response.json().get("data", {}).get("children", [])

        discussions = []
        for post in posts[:5]:
            data = post.get("data", {})
            title = data.get("title", "")
            score = data.get("score", 0)
            subreddit = data.get("subreddit", "")
            discussions.append(f"r/{subreddit} ({score} upvotes): {title}")

        return discussions if discussions else ["No major Reddit discussions found."]
    except Exception as e:
        return [f"Reddit fetch error: {str(e)}"]

# Analyze domain
def analyze_website(domain):
    cache_key = domain.lower()
    if cache_key in analysis_cache and datetime.now() < analysis_cache[cache_key]['expires']:
        return analysis_cache[cache_key]['report']

    reddit_discussions = get_reddit_sentiment(domain)

    prompt = f"""
Analyze this website for legitimacy: {domain}

Recent Reddit Discussions:
{chr(10).join(reddit_discussions)}

Required Analysis:
1. Verify domain authenticity (.gov.vn etc.)
2. Analyze Reddit sentiment
3. Check for common scam patterns
4. Evaluate professional indicators

Response Format:

🚨 SCAM RISK: XX% (or "Confirmed Legitimate")

🔍 Verification:
- Domain Type: [.gov/.com/etc.]
- SSL Security: [Yes/No]
- Known Official: [Yes/No/Uncertain]

📊 Community Reports:
{chr(10).join(f"- {d}" for d in reddit_discussions)}

⚠️ Red Flags:
1.
2.
3.

✅ Trust Indicators:
1.
2.

💡 Final Recommendation:
[2-3 sentence verdict]
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )
        report = response.choices[0].message.content.strip()
        analysis_cache[cache_key] = {
            'report': report,
            'expires': datetime.now() + timedelta(hours=6)
        }
        return report
    except Exception as e:
        return f"🚨 ANALYSIS FAILED\nError: {str(e)}"

# Home route – set session cookie early
@app.route('/')
def home():
    response = make_response(send_from_directory('.', 'index.html'))
    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = str(uuid.uuid4())
        response.set_cookie(
            'session_id',
            value=session_id,
            max_age=30 * 24 * 60 * 60,
            httponly=True,
            samesite='Lax'
        )
    return response

# Main check route
@app.route('/check', methods=['POST'])
def check_domain():
    data = request.get_json()
    domain = data.get('domain', '').strip()

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = str(uuid.uuid4())

    if session_id not in sessions:
        sessions[session_id] = {
            'free_checks_remaining': 1,
            'paid': False,
            'created_at': datetime.now()
        }

    session = sessions[session_id]

    if session['paid'] or session['free_checks_remaining'] > 0:
        if domain == 'status-check':
            return jsonify({
                "status": "unlocked" if session['paid'] else "free",
                "report": "Session updated."
            })

        report = analyze_website(domain)

        if not session['paid']:
            session['free_checks_remaining'] -= 1

        status = "unlocked" if session['paid'] else "free"
        response = jsonify({
            "status": status,
            "report": report
        })
        response.set_cookie(
            'session_id',
            value=session_id,
            max_age=30 * 24 * 60 * 60,
            httponly=True,
            samesite='Lax'
        )
        return response
    else:
        return jsonify({
            "status": "locked",
            "payment_url": "https://akiagi3.gumroad.com/l/bhphh"
        })

# Gumroad redirect
@app.route('/verify-payment', methods=['GET'])
def verify_payment():
    session_id = request.cookies.get('session_id')
    response = redirect('/?payment=success')

    if not session_id:
        session_id = str(uuid.uuid4())
        response.set_cookie(
            'session_id',
            value=session_id,
            max_age=30 * 24 * 60 * 60,
            httponly=True,
            samesite='Lax'
        )

    if session_id not in sessions:
        sessions[session_id] = {
            'paid': True,
            'free_checks_remaining': float('inf'),
            'created_at': datetime.now()
        }
    else:
        sessions[session_id]['paid'] = True
        sessions[session_id]['free_checks_remaining'] = float('inf')

    return response

# Run the server
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
