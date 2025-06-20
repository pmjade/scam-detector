from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS
from openai import OpenAI
import os
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", str(uuid.uuid4()))
CORS(app, supports_credentials=True)  # Enable cookies

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Server-side session storage
sessions = {}

@app.route('/check', methods=['POST'])
def check_domain():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    # Get or create session ID from cookie
    session_id = request.cookies.get('session_id', str(uuid.uuid4()))
    
    # Initialize session if new
    if session_id not in sessions:
        sessions[session_id] = {
            'free_checks_remaining': 1,
            'paid': False,
            'created_at': datetime.now()
        }

    # Check access rights
    if sessions[session_id]['paid'] or sessions[session_id]['free_checks_remaining'] > 0:
        analysis = analyze_website(domain)  # Your existing analysis function
        
        if not sessions[session_id]['paid']:
            sessions[session_id]['free_checks_remaining'] -= 1

        response = jsonify({
            "status": "free" if sessions[session_id]['free_checks_remaining'] >= 0 else "unlocked",
            "report": analysis
        })
        
        # Set persistent cookie (expires in 30 days)
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

def get_reddit_sentiment(domain):
    """Fetch Reddit discussions about the domain"""
    headers = {'User-agent': 'ScamDetectorBot/1.0'}
    try:
        response = requests.get(
            f"https://www.reddit.com/search.json?q={domain}&limit=5",
            headers=headers
        )
        posts = response.json().get('data', {}).get('children', [])
        
        discussions = []
        for post in posts:
            title = post['data'].get('title', '')
            comments = post['data'].get('num_comments', 0)
            if comments > 0:
                discussions.append(f"{title} ({comments} comments)")
        
        return discussions[:3] if discussions else ["No recent discussions found"]
    except Exception as e:
        print(f"Reddit API error: {e}")
        return ["Could not fetch Reddit data"]

def analyze_website(domain):
    """Enhanced website analysis with real-time data"""
    # Check cache first
    cache_key = domain.lower()
    if cache_key in analysis_cache:
        if datetime.now() < analysis_cache[cache_key]['expires']:
            return analysis_cache[cache_key]['report']
    
    # Get external data
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
    
    if not results:
    return "No major Reddit discussions found. Consider searching manually for user experiences."

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
        
        # Cache results for 6 hours
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

    session_id = request.headers.get('X-Session-ID', str(uuid.uuid4()))
    
    if session_id in paid_sessions or session_id not in usage_tracker:
        analysis = analyze_website(domain)
        usage_tracker[session_id] = True
        return jsonify({
            "status": "free" if session_id not in usage_tracker else "unlocked",
            "report": analysis,
            "session_id": session_id
        })
    else:
        return jsonify({
            "status": "locked",
            "payment_url": GUMROAD_PRODUCT_URL
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
