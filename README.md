# OWASP Top 10 Analyzer 🛡️

A powerful vulnerability scanner that checks websites for OWASP Top 10 risks using Python, Flask, and AI-powered fix suggestions. Includes real-time progress bar, CVSS scoring, HTML/PDF/JSON reporting, and an interactive dashboard.

---

## 🔍 Features

- ✅ Scans all OWASP Top 10 categories
- 📊 Flask web dashboard with charts
- 📈 CVSS scoring & risk levels
- 🧠 AI-based fix suggestions
- 🧾 Exports reports as HTML, JSON, PDF
- ⏳ Real-time terminal progress bar
- 📦 Ready for GitHub portfolio and Docker deployment

---

## 🚀 Getting Started

### 1. Clone the Project
```bash
git clone https://github.com/yourusername/owasp-top10-analyzer.git
cd owasp-top10-analyzer
```

### 2. Install Requirements
```bash
pip install -r requirements.txt
```

### 3. Run CLI Scanner (Terminal)
```bash
python main.py
```

### 4. Launch Flask Web UI
```bash
cd flask_app
python app.py
```
Then open: `http://localhost:5000`

---

## 📁 Project Structure
```
├── main.py                     # CLI scanner
├── flask_app/
│   ├── app.py                 # Flask backend
│   ├── templates/             # HTML views
│   ├── static/                # Chart.js (optional)
├── scanner/                   # OWASP modules
├── utils/
│   ├── report_generator.py    # HTML/PDF/JSON exporters
│   ├── cvss_calculator.py     # Assigns CVSS + risk
│   ├── fixer.py               # AI-based fix suggestions
├── reports/                   # CLI reports
├── flask_reports/             # Web UI reports
```

---

## 🧪 Supported OWASP Categories
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable & Outdated Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring
- A10: Server-Side Request Forgery (SSRF)

---

## 📷 Screenshots
Add screenshots of:
- Web dashboard
- Sample scan results
- Charts
- Fix suggestions

---

## 🧠 AI Fix Suggestions
Each vulnerability is paired with a practical mitigation tip generated using internal logic in `fixer.py`, suitable for DevSecOps teams and educational demos.

---

## 📦 Coming Soon
- Docker deployment
- Auth-protected dashboard
- Scheduled auto-scans
- Slack/email alert integration

---

## 👨‍💻 Author
[Your Name](https://www.linkedin.com/in/yourprofile)  
Master’s in Cybersecurity | OWASP Enthusiast | Python Developer

---

## 📜 License
MIT License
