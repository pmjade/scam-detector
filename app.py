import os
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

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

def generate_scam_report(domain):
    return {
        "domain": domain,
        "scam_score": 82,
        "details": "Suspicious activity detected for this domain."
    }

@app.route("/")
def home():
    return render_template_string("""
        <html><body>
            <h1>Scam Detector 🔍</h1>
            <form action="/check" method="post">
                <input type="text" name="domain" placeholder="Enter domain...">
                <button type="submit">Check</button>
            </form>
            <p><a href="/unlock-page">Unlock with license key</a></p>
        </body></html>
    """)

@app.route("/check", methods=["POST"])
def check():
    if request.is_json:
        # === FROM JS FETCH ===
        data = request.get_json()
        domain = data.get("domain")
        ip = request.remote_addr

        if not domain:
            return jsonify({"status": "error", "message": "No domain"}), 400

        if ip in free_usage_tracker:
            return jsonify({"status": "locked"}), 403

        free_usage_tracker.add(ip)
        save_usage(free_usage_tracker)
        return jsonify({"status": "ready"})

    else:
        # === FROM HTML FORM ===
        domain = request.form.get("domain")
        ip = request.remote_addr

        if ip in free_usage_tracker:
            return render_template_string("<p>Already used your free scan. <a href='/'>Back</a></p>")

        free_usage_tracker.add(ip)
        save_usage(free_usage_tracker)
        report = generate_scam_report(domain)
        return render_template_string(f"""
            <p>✅ Domain: {report['domain']}</p>
            <p>Scam Score: {report['scam_score']}</p>
            <p>{report['details']}</p>
            <a href="/">Back</a>
        """)

@app.route("/unlock", methods=["POST"])
def unlock():
    if request.is_json:
        # === JS FETCH ===
        data = request.get_json()
        domain = data.get("domain")
        license_key = data.get("key")
        valid_key = os.environ.get("LICENSE_KEY", "DEFAULT_SECRET_KEY")

        if license_key != valid_key:
            return jsonify({"status": "error", "message": "Invalid key"}), 403

        report = generate_scam_report(domain)
        return jsonify({"report": f"""
Domain: {report['domain']}
Scam Score: {report['scam_score']}
Details: {report['details']}
        """})

    else:
        # === HTML FORM ===
        domain = request.form.get("domain")
        license_key = request.form.get("license_key")
        valid_key = os.environ.get("LICENSE_KEY", "DEFAULT_SECRET_KEY")

        if license_key != valid_key:
            return "<p>Invalid key</p><a href='/'>Back</a>", 403

        report = generate_scam_report(domain)
        return render_template_string(f"""
            <p>✅ Domain: {report['domain']}</p>
            <p>Scam Score: {report['scam_score']}</p>
            <p>{report['details']}</p>
            <a href="/">Back</a>
        """)

@app.route("/unlock-page")
def unlock_page():
    return render_template_string("""
        <form method="post" action="/unlock">
            <input name="domain" placeholder="domain" required><br>
            <input name="license_key" placeholder="key" required><br>
            <button>Unlock</button>
        </form>
    """)

@app.route("/ping")
def ping():
    return "pong", 200

if __name__ == "__main__":
    app.run(debug=False)
