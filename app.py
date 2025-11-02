import re
import logging
import csv
import io
from datetime import datetime
from typing import List, Dict, Any, Optional

from flask import Flask, request, jsonify, render_template, send_file
import requests

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

BASE_URL = "https://gmailver.com"
KEY_ENDPOINT = f"{BASE_URL}/php/key.php"
CHECK_ENDPOINT = f"{BASE_URL}/php/check1.php"

BROWSER_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9,bn;q=0.8",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "upgrade-insecure-requests": "1",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/141.0.0.0 Safari/537.36"
    ),
    "sec-ch-ua": '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "referer": f"{BASE_URL}/",
}

API_HEADERS = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "en-US,en;q=0.9,bn;q=0.8",
    "content-type": "application/json;charset=UTF-8",
    "origin": BASE_URL,
    "referer": f"{BASE_URL}/",
    "user-agent": BROWSER_HEADERS["user-agent"],
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "sec-ch-ua": BROWSER_HEADERS["sec-ch-ua"],
    "sec-ch-ua-mobile": BROWSER_HEADERS["sec-ch-ua-mobile"],
    "sec-ch-ua-platform": BROWSER_HEADERS["sec-ch-ua-platform"],
}

def extract_key_from_text(text: str) -> str:
    m = re.search(r"([0-9a-fA-F]{24,64})", text or "")
    return m.group(1) if m else ""

def fetch_cookies_requests() -> Optional[requests.Session]:
    s = requests.Session()
    s.headers.update(BROWSER_HEADERS)
    r = s.get(BASE_URL + "/", timeout=30, allow_redirects=True)
    if r.status_code == 200:
        return s
    if r.cookies and len(r.cookies) > 0:
        return s
    return None

def fetch_cookies_selenium() -> Optional[requests.Session]:
    try:
        import undetected_chromedriver as uc
        from selenium.webdriver.chrome.options import Options
    except Exception:
        return None

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--window-size=1200,900")

    driver = uc.Chrome(options=opts)
    try:
        driver.get(BASE_URL + "/")
        driver.implicitly_wait(5)
        cookies = driver.get_cookies()
        if not cookies:
            return None

        s = requests.Session()
        s.headers.update(BROWSER_HEADERS)
        for ck in cookies:
            s.cookies.set(ck.get("name"), ck.get("value"), domain=ck.get("domain"), path=ck.get("path"))
        return s
    finally:
        driver.quit()

def session_from_cookie_string(cookie_str: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(BROWSER_HEADERS)
    for part in re.split(r"[;,\n]+", cookie_str):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        s.cookies.set(k.strip(), v.strip(), domain="gmailver.com", path="/")
    return s

def get_session_with_cookies(manual_cookie: Optional[str] = None) -> requests.Session:
    if manual_cookie:
        return session_from_cookie_string(manual_cookie)

    s = fetch_cookies_requests()
    if s:
        return s

    s = fetch_cookies_selenium()
    if s:
        return s

    s = requests.Session()
    s.headers.update(BROWSER_HEADERS)
    return s

def call_key(session: requests.Session, mails: List[str]) -> Dict[str, Any]:
    payload = {"mail": mails}
    r = session.post(KEY_ENDPOINT, json=payload, headers=API_HEADERS, timeout=60)
    raw = r.text or ""
    key = extract_key_from_text(raw)
    return {"ok": bool(key), "key": key, "raw": raw[:2000], "status": r.status_code}

def call_check(session: requests.Session, mails: List[str], key: str, fast_check: bool) -> Dict[str, Any]:
    payload = {"mail": mails, "key": key, "fastCheck": bool(fast_check)}
    r = session.post(CHECK_ENDPOINT, json=payload, headers=API_HEADERS, timeout=90)
    try:
        return {"json": r.json(), "status": r.status_code}
    except ValueError:
        return {"raw": r.text[:50000], "status": r.status_code}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/check", methods=["POST"])
def api_check():
    body = request.get_json(silent=True) or {}
    mails = body.get("mail") or []
    fast_check = bool(body.get("fastCheck", False))
    manual_cookie = body.get("cookie")

    if not isinstance(mails, list) or not mails:
        return jsonify({"error": "Provide a non-empty 'mail' list"}), 400

    session = get_session_with_cookies(manual_cookie)

    try:
        key_resp = call_key(session, mails)
    except requests.RequestException as e:
        return jsonify({"error": "key endpoint failed", "detail": str(e)}), 502

    if not key_resp.get("ok"):
        return jsonify({
            "error": "Could not extract key",
            "status": key_resp.get("status"),
            "key_raw": key_resp.get("raw")
        }), 502

    key = key_resp["key"]

    try:
        check_resp = call_check(session, mails, key, fast_check)
    except requests.RequestException as e:
        return jsonify({"error": "check endpoint failed", "detail": str(e), "key": key}), 502

    friendly = {}
    detailed_results = []
    
    if "json" in check_resp and isinstance(check_resp["json"], dict):
        data = check_resp["json"]
        if isinstance(data.get("data"), list):
            for item in data["data"]:
                mail = item.get("mail") or item.get("email")
                status = item.get("status") or item.get("state") or "unknown"
                if mail:
                    friendly[mail] = status
                    detailed_results.append({
                        "email": mail,
                        "status": status,
                        "timestamp": datetime.now().isoformat()
                    })
        else:
            for k, v in data.items():
                if isinstance(k, str) and "@" in k:
                    friendly[k] = v
                    detailed_results.append({
                        "email": k,
                        "status": v,
                        "timestamp": datetime.now().isoformat()
                    })

    return jsonify({
        "input_count": len(mails),
        "key": key,
        "remote": check_resp,
        "summary": friendly or None,
        "detailed_results": detailed_results,
        "timestamp": datetime.now().isoformat()
    })

@app.route("/api/download", methods=["POST"])
def download_results():
    data = request.get_json(silent=True) or {}
    results = data.get("results", [])
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Serial", "Email", "Status", "Timestamp"])
    
    for idx, result in enumerate(results, 1):
        writer.writerow([
            idx,
            result.get("email", ""),
            result.get("status", ""),
            result.get("timestamp", "")
        ])
    
    output.seek(0)
    
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'gmail_check_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

if __name__ == "__main__":
    app.run(debug=True, port=5000)
