from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS
from openai import OpenAI
import os
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", str(uuid.uuid4()))
CORS(app, supports_credentials=True)

# Initialize OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Server-side session storage
sessions = {}

def analyze_website(domain):
    """Your existing analysis function"""
    return "Sample report"  # Replace with your actual analysis code

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
    
    # Initialize session if new
    if session_id not in sessions:
        sessions[session_id] = {
            'free_checks_remaining': 1,
            'paid': False,
            'created_at': datetime.now()
        }

    # Check access rights
    if sessions[session_id]['paid'] or sessions[session_id]['free_checks_remaining'] > 0:
        analysis = analyze_website(domain)
        
        if not sessions[session_id]['paid']:
            sessions[session_id]['free_checks_remaining'] -= 1

        response = jsonify({
            "status": "free" if sessions[session_id]['free_checks_remaining'] >= 0 else "unlocked",
            "report": analysis
        })
        
        # Set persistent cookie
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
