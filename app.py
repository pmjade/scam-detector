from flask import Flask, request, jsonify
import time

app = Flask(__name__)

# Store reports temporarily
temp_report_cache = {}

# Track free usage by IP
free_usage_tracker = set()

# Dummy function to simulate scam report generation
def generate_scam_report(domain):
    time.sleep(2)  # simulate processing time
    return {
        "domain": domain,
        "scam_score": 75,
        "details": "Suspicious patterns detected."
    }

# === HOME ===
@app.route("/")
def home():
    return "Scam Detector is running!"

# === CHECK ROUTE (Handles free usage) ===
@app.route('/check', methods=["POST"])
def check():
    domain = request.json.get("domain")
    user_ip = request.remote_addr

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    # Already used free check
    if user_ip in free_usage_tracker:
        return jsonify({
            "status": "locked",
            "message": "You've already used your free scam check. Unlock unlimited scans for just €2.",
            "unlock_url": "https://akiagi3.gumroad.com/l/bhphh"  # Replace with your Gumroad product URL
        })

    # First-time free usage
    free_usage_tracker.add(user_ip)
    report = generate_scam_report(domain)
    return jsonify({
        "status": "unlocked",
        "message": "This was your free scam check!",
        "report": report
    })

# === UNLOCK ROUTE (For paid users with license key) ===
@app.route('/unlock', methods=["POST"])
def unlock():
    domain = request.json.get("domain")
    license_key = request.json.get("license_key")

    # TODO: Add real license key verification here
    if license_key != "SECRET123":  # Replace this logic with actual Gumroad verification
        return jsonify({"error": "Invalid license key"}), 403

    report = generate_scam_report(domain)
    return jsonify({
        "status": "unlocked",
        "message": "Access granted via license key.",
        "report": report
    })

# === RUN ===
if __name__ == "__main__":
    app.run(debug=True)

