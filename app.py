import os
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Use a file for free check usage tracking
USAGE_FILE = 'free_usage.txt'

def load_usage():
    if os.path.exists(USAGE_FILE):
        with open(USAGE_FILE, 'r') as f:
            return set(f.read().splitlines())
    return set()

def save_usage(usage_set):
    with open(USAGE_FILE, 'w') as f:
        for ip in usage_set:
            f.write(ip + '\n')

free_usage_tracker = load_usage()

@app.route("/ping")
def ping():
    return "pong", 200

# Simulate scam detection
def generate_scam_report(domain):
    return {
        "domain": domain,
        "scam_score": 82,
        "details": "Suspicious activity detected for this domain."
    }

# === BASIC HOME PAGE ===
@app.route("/")
def home():
    return render_template_string("""
        <html>
        <head>
            <title>Scam Detector</title>
            <style>
                body { font-family: Arial; text-align: center; padding-top: 50px; background: #f7f7f7; }
                input, button { padding: 10px; margin: 5px; }
                .box { background: white; padding: 30px; border-radius: 10px; display: inline-block; }
            </style>
        </head>
        <body>
            <div class="box">
                <h1>Scam Detector 🔍</h1>
                <form action="/check" method="post">
                    <input type="text" name="domain" placeholder="Enter domain..." required><br>
                    <button type="submit">Check for Free</button>
                </form>
                <p>Already used free check? <a href="/unlock-page">Unlock with License Key</a></p>
            </div>
        </body>
        </html>
    """)

# === FREE CHECK FORM SUBMIT ===
@app.route("/check", methods=["POST"])
def check():
    domain = request.form.get("domain")
    user_ip = request.remote_addr

    if not domain:
        return "No domain provided", 400

    if user_ip in free_usage_tracker:
        return render_template_string("""
            <html><body>
                <h2>🔒 You've already used your free scam check!</h2>
                <p>Unlock unlimited scans for just €2:</p>
                <a href="https://akiagi3.gumroad.com/l/bhphh">Buy License Key</a>
                <br><br><a href="/">← Go Back</a>
            </body></html>
        """)

    free_usage_tracker.add(user_ip)
    save_usage(free_usage_tracker) # Save usage after adding
    report = generate_scam_report(domain)
    return render_template_string(f"""
        <html><body>
            <h2>✅ Report for: {report['domain']}</h2>
            <p>Scam Score: {report['scam_score']}</p>
            <p>Details: {report['details']}</p>
            <br><a href="/">← Go Back</a>
        </body></html>
    """)

# === LICENSE KEY UNLOCK PAGE ===
@app.route("/unlock-page")
def unlock_page():
    return render_template_string("""
        <html><body>
            <h2>🔑 Enter License Key to Unlock Scam Check</h2>
            <form action="/unlock" method="post">
                <input type="text" name="domain" placeholder="Domain..." required><br>
                <input type="text" name="license_key" placeholder="Your License Key" required><br>
                <button type="submit">Unlock</button>
            </form>
            <br><a href="/">← Go Back</a>
        </body></html>
    """)

# === UNLOCK WITH LICENSE ===
@app.route("/unlock", methods=["POST"])
def unlock():
    domain = request.form.get("domain")
    license_key = request.form.get("license_key")

    # Get license key from environment variable
    EXPECTED_LICENSE_KEY = os.environ.get('LICENSE_KEY', 'DEFAULT_SECRET_KEY') # Provide a default for local testing

    if license_key != EXPECTED_LICENSE_KEY:
        return "<h2>❌ Invalid license key</h2><br><a href='/'>← Go Back</a>", 403

    report = generate_scam_report(domain)
    return render_template_string(f"""
        <html><body>
            <h2>✅ Report for: {report['domain']}</h2>
            <p>Scam Score: {report['scam_score']}</p>
            <p>Details: {report['details']}</p>
            <br><a href="/">← Go Back</a>
        </body></html>
    """)

if __name__ == "__main__":
    app.run(debug=False) # Set debug to False for production
