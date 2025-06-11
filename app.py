from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from openai import OpenAI
import requests, os
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")
GUMROAD_PRODUCT_ID = os.getenv("GUMROAD_PRODUCT_ID")

app = Flask(__name__, template_folder='.')  # ⬅️ Tells Flask "index.html is in root"
CORS(app)

temp_report_cache = {}

def check_domain_info(domain):
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON"
    try:
        r = requests.get(url)
        data = r.json()
        reg = data["WhoisRecord"]["createdDate"]
        org = data["WhoisRecord"]["registryData"]["registrant"]["organization"]
        return f"Registered: {reg}\nOwner: {org}"
    except:
        return "Info not available."

def generate_scam_report(domain):
    if domain in temp_report_cache:
        return temp_report_cache[domain]
    info = check_domain_info(domain)
    prompt = f"Check if this is a scam: {domain}\nInfo: {info}"
    res = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.5, max_tokens=300
    )
    report = res.choices[0].message.content
    temp_report_cache[domain] = report
    return report

def verify_gumroad_license(key):
    url = "https://api.gumroad.com/v2/licenses/verify"
    r = requests.post(url, data={
        "product_permalink": GUMROAD_PRODUCT_ID,
        "license_key": key
    })
    return r.json().get("success", False)

@app.route('/')
def home():
    return render_template("index.html")  # ✅ this now works because index.html is in root

@app.route('/check', methods=["POST"])
def check():
    domain = request.json.get("domain")
    if not domain:
        return jsonify({"error": "No domain"}), 400
    generate_scam_report(domain)
    return jsonify({"status": "ready", "message": "Report is ready. Click below to unlock!"})

@app.route('/unlock', methods=["POST"])
def unlock():
    data = request.json
    domain = data.get("domain")
    key = data.get("key")
    if not domain or not key:
        return jsonify({"error": "Missing domain or key"}), 400
    if not verify_gumroad_license(key):
        return jsonify({"error": "Invalid key"}), 403
    report = temp_report_cache.get(domain)
    if not report:
        return jsonify({"error": "Report expired or not found"}), 404
    return jsonify({"report": report})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)

