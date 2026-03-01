# Real-Time SOC Threat Dashboard 🛡️

A lightweight, real-time security monitoring interface designed for SOC Analysts to detect and respond to infrastructure threats. 

## 🚀 Features
* **Live Log Monitoring:** Automatically tracks system logs for new entries.
* **Attack Detection:** Uses Regex patterns to identify:
    * **Brute Force:** 5+ failed logins from a single IP.
    * **SQL Injection:** Detects common payloads like `UNION` and `' OR 1=1`.
    * **Directory Traversal:** Flags attempts to access sensitive paths like `/etc/passwd`.
* **Visual Alerts:** Color-coded dashboard for rapid severity assessment (Critical/Warning).
* **Forensic Export:** One-click export of suspicious logs to JSON for incident reporting.

## 🛠️ Tech Stack
* **Backend:** Python, Flask
* **Frontend:** HTML5, CSS3 (Dark Theme)
* **Testing:** Mock Traffic Generator (Python)

## 📸 Screenshots
![Main Dashboard UI](./screenshots/dashboard_main.png)
*Example of the real-time alert feed.*

## ⚙️ Installation & Usage
1. Clone the repo: `git clone https://github.com/yourusername/soc-threat-dashboard.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Start the dashboard: `python app.py`
4. (Optional) Run the attack simulator: `python log_generator.py`
