from flask import Flask, request, jsonify, make_response, redirect
from datetime import datetime, timedelta
import requests
import uuid
import atexit
import pickle
import openai

app = Flask(__name__)

# In-memory session and cache
sessions = {}
analysis_cache = {}

# Load sessions from disk
try:
    with open('sessions.pkl', 'rb') as f:
        sessions.update(pickle.load(f))
except:
    pass

# Save sessions on exit
def save_sessions():
    with open('sessions.pkl', 'wb') as f:
        pickle.dump(sessions, f)

atexit.register(save_sessions)

# Set your OpenAI API key
openai.api_key = "your-openai-key-here"

@app.route('/')
def index():
    return open('index.html').read()

@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    domain = data.get('domain')

    # Get or create session
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in sessions:
        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            'free_checks_remaining': 1,
            'paid': False
        }

    session = sessions[session_id]

    # Free users have 1 try
    if not session['paid'] and session['free_checks_remaining'] <= 0:
        response = jsonify({
            'status': 'payment_required',
            'payment_url': 'https://verifina.gumroad.com/l/verify-domain'
        })
        response.set_cookie('session_id', session_id, max_age=30 * 24 * 60 * 60)
        return response

    if not session['paid']:
        session['free_checks_remaining'] -= 1

    # Skip real analysis if status-check used
    if domain == 'status-check':
        return jsonify({'status': 'free', 'report': '✅ Session updated.'})

    report = analyze_website(domain)
    response = jsonify({
        'status': 'free' if not session['paid'] else 'premium',
        'report': report
    })
    response.set_cookie('session_id', session_id, max_age=30 * 24 * 60 * 60)
    return response

@app.route('/verify-payment', methods=['GET'])
def verify_payment():
    session_id = request.cookies.get('session_id')
    if session_id in sessions:
        sessions[session_id]['paid'] = True
        sessions[session_id]['free_checks_remaining'] = float('inf')
    return redirect('/?payment=success')

def get_reddit_sentiment(domain):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        url = f"https://www.reddit.com/search.json?q={domain}&sort=new"
        res = requests.get(url, headers=headers)
        posts = res.json()['data']['children']
        discussions = []
        for post in posts[:5]:
            title = post['data']['title']
            subreddit = post['data']['subreddit']
            permalink = post['data']['permalink']
            discussions.append(f"[{subreddit}] {title} - https://reddit.com{permalink}")
        return discussions or ["No major Reddit discussions found."]
    except Exception:
        return ["Failed to fetch Reddit discussions."]

def analyze_website(domain):
    cache_key = domain.lower()
    if cache_key in analysis_cache:
        if datetime.now() < analysis_cache[cache_key]['expires']:
            return analysis_cache[cache_key]['report']

    reddit_discussions = get_reddit_sentiment(domain)

    prompt = f"""
    Analyze this website for legitimacy: {domain}

    **Recent Reddit Discussions:**
    {chr(10).join(reddit_discussions)}

    **Required Analysis:**
    1. Verify domain authenticity (.gov.vn etc.)
    2. Analyze Reddit sentiment
    3. Check for common scam patterns
    4. Evaluate professional indicators

    **Response Format:**

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
        response = openai.ChatCompletion.create(
            model="gpt-4-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )
        report = response.choices[0].message['content'].strip()
        analysis_cache[cache_key] = {
            'report': report,
            'expires': datetime.now() + timedelta(hours=6)
        }
        return report
    except Exception as e:
        return f"🚨 ANALYSIS FAILED\nError: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)

