from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS
from openai import OpenAI
import os
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv
import requests

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

# Get Reddit discussions
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

# Analyze website
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

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/check', methods=['POST'])
def check_domain():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    # Get or create session ID from cookie
    session_id = request.cookies.get('session_id', str(uuid.uuid4()))
    
    if session_id not in sessions:
        sessions[session_id] = {
            'free_checks_remaining': 1,
            'paid': False,
            'created_at': datetime.now()
        }

    # Access check logic
    if sessions[session_id]['paid'] or sessions[session_id]['free_checks_remaining'] > 0:
        report = analyze_website(domain)

        if not sessions[session_id]['paid']:
            sessions[session_id]['free_checks_remaining'] -= 1

        status = "unlocked" if sessions[session_id]['paid'] else "free"
        response = jsonify({
            "status": status,
            "report": report
        })

        # Cookie for session tracking
        response.set_cookie(
            'session_id',
            value=session_id,
            max_age=30*24*60*60,
            httponly=True,
            samesite='Lax'
        )

        return response

    else:
        return jsonify({
            "status": "locked",
            "payment_url": "https://akiagi3.gumroad.com/l/bhphh"
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))

