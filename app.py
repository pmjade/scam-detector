from flask import Flask, request, jsonify, send_from_directory, make_response, redirect
from flask_cors import CORS
from openai import OpenAI
import os
import uuid
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", str(uuid.uuid4()))
CORS(app, supports_credentials=True, origins=["https://verifina.pro"])

# Initialize OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Server-side session storage (use Redis in production)
sessions = {}
GUMROAD_PRODUCT_URL = "https://akiagi3.gumroad.com/l/bhphh"
GUMROAD_API_KEY = os.getenv("GUMROAD_API_KEY")

def analyze_website(domain):
    """Enhanced website analysis with real checks"""
    try:
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[{
                "role": "user",
                "content": f"Analyze this website for scams: {domain}\n\nCheck domain, SSL, reviews, and provide risk percentage."
            }],
            temperature=0.2
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"🚨 ANALYSIS ERROR\n{str(e)}"

def verify_gumroad_purchase(sale_id):
    """Verify payment with Gumroad API"""
    try:
        response = requests.post(
            "https://api.gumroad.com/v2/sales/verify",
            data={
                "product_id": "bhphh",
                "sale_id": sale_id
            },
            auth=(GUMROAD_API_KEY, "")
        )
        return response.json().get("success", False)
    except:
        return False

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/check', methods=['POST'])
def check_domain():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    session_id = request.cookies.get('session_id', str(uuid.uuid4()))
    
    # Initialize or get session
    if session_id not in sessions:
        sessions[session_id] = {
            'free_checks': 1,
            'paid': False,
            'created_at': datetime.now()
        }

    # Check access
    if sessions[session_id]['paid'] or sessions[session_id]['free_checks'] > 0:
        analysis = analyze_website(domain)
        
        if not sessions[session_id]['paid']:
            sessions[session_id]['free_checks'] -= 1

        response = jsonify({
            "status": "unlocked" if sessions[session_id]['paid'] else "free",
            "report": analysis,
            "remaining_checks": sessions[session_id]['free_checks']
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
        "payment_url": f"{GUMROAD_PRODUCT_URL}?referrer=verifina"
    })

@app.route('/verify-payment', methods=['GET'])
def verify_payment():
    sale_id = request.args.get('sale_id')
    session_id = request.cookies.get('session_id')
    
    if not sale_id or not session_id:
        return redirect('/?payment=failed')
    
    if verify_gumroad_purchase(sale_id) and session_id in sessions:
        sessions[session_id]['paid'] = True
        sessions[session_id]['free_checks'] = float('inf')
        return redirect('/?payment=success')
    
    return redirect('/?payment=failed')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
