import os
import re
import time
import json
import threading
from datetime import datetime
from collections import defaultdict
from flask import Flask, jsonify, render_template

app = Flask(__name__)

# Alerts list to store recent alerts
alerts = []
# Dictionary to track failed logins: { ip: [timestamp1, timestamp2, ...] }
failed_logins = defaultdict(list)

LOG_FILE = "access.log"

# Regex patterns
DIR_TRAVERSAL_RE = re.compile(r'(?:\.\./|/etc/passwd)', re.IGNORECASE)
SQLI_RE = re.compile(r'(?:SELECT |UNION |\' OR 1=1)', re.IGNORECASE)
FAILED_LOGIN_RE = re.compile(r'^(\d+\.\d+\.\d+\.\d+) .* "(?:GET|POST) .* HTTP.*" 401 ')

def add_alert(alert_type, severity, description, ip="Unknown", timestamp=None):
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert = {
        "timestamp": timestamp,
        "type": alert_type,
        "severity": severity,
        "description": description,
        "ip": ip
    }
    alerts.append(alert)
    # Keep only the last 100 alerts to prevent memory bounding issues
    if len(alerts) > 100:
        alerts.pop(0)

def extract_ip_timestamp_from_log(line):
    # Basic parse: "192.168.1.1 - [01/Mar/2026..."
    parts = line.split(" ", 3)
    ip = parts[0] if len(parts) > 0 else "Unknown"
    return ip

def process_log_line(line):
    line_upper = line.upper()
    ip = extract_ip_timestamp_from_log(line)
    
    # 1. Directory Traversal
    if DIR_TRAVERSAL_RE.search(line):
        add_alert("Directory Traversal", "Critical", f"Detected path traversal attempt", ip)

    # 2. SQL injection
    elif SQLI_RE.search(line):
        add_alert("SQL Injection", "Critical", f"Detected SQLi payload", ip)

    # 3. Brute Force
    match = FAILED_LOGIN_RE.search(line)
    if match:
        login_ip = match.group(1)
        now = time.time()
        # Clean up old timestamps (older than 30 seconds)
        failed_logins[login_ip] = [ts for ts in failed_logins[login_ip] if now - ts <= 30]
        
        failed_logins[login_ip].append(now)
        
        if len(failed_logins[login_ip]) >= 5:
            add_alert("Brute Force Attempt", "Critical", f"5+ failed logins from {login_ip} in 30s", login_ip)
            # Clear to avoid spamming alerts for this IP immediately, although in real SOC we might want to keep it
            failed_logins[login_ip] = []
        else:
            add_alert("Failed Login", "Warning", f"Failed authentication attempt", login_ip)

def monitor_log():
    # Wait until the file exists
    while not os.path.exists(LOG_FILE):
        time.sleep(1)
        
    with open(LOG_FILE, 'r') as f:
        # Seek to the end of the file initially
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            process_log_line(line)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def api_alerts():
    return jsonify(alerts)

@app.route('/api/export')
def api_export():
    critical_alerts = [a for a in alerts if a['severity'] == "Critical"]
    with open('threat_report.json', 'w') as f:
        json.dump(critical_alerts, f, indent=4)
    return jsonify({"status": "success", "message": f"Exported {len(critical_alerts)} critical alerts to threat_report.json"}), 200

def start_monitor():
    t = threading.Thread(target=monitor_log, daemon=True)
    t.start()

if __name__ == '__main__':
    start_monitor()
    app.run(debug=True, use_reloader=False)

