
# Web Application Vulnerability Scanner

A Python-based automated security testing tool that detects common web application vulnerabilities including SQL Injection, Cross-Site Scripting (XSS), and Cross-Site Request Forgery (CSRF). Built as part of cybersecurity internship project demonstrating practical penetration testing skills.

## 🎯 Project Overview

This scanner automates the detection of OWASP Top 10 vulnerabilities by crawling web applications, identifying input vectors, and testing them with various attack payloads. It provides detailed reporting with severity levels and proof-of-concept evidence.

## ✨ Features

- **SQL Injection Detection**
  - 9+ specialized injection payloads
  - Error-based detection with regex pattern matching
  - Tests for authentication bypass
  - Identifies MySQL, PostgreSQL, MSSQL, and Oracle vulnerabilities

- **Cross-Site Scripting (XSS) Detection**
  - 8+ XSS payloads for reflected vulnerabilities
  - JavaScript injection testing
  - Event handler exploitation
  - SVG and iframe-based attacks

- **CSRF Vulnerability Detection**
  - Validates presence of CSRF tokens
  - Checks POST form security
  - Identifies unprotected state-changing operations

- **Automated Features**
  - Intelligent form crawling using BeautifulSoup
  - Automatic input field detection
  - Real-time scan progress tracking
  - SQLite database for scan history
  - Web-based dashboard interface

## 🛠️ Technologies Used

- **Backend:** Python 3.x, Flask
- **Web Scraping:** BeautifulSoup4, Requests
- **Database:** SQLite
- **Frontend:** HTML5, CSS3, JavaScript
- **Security Testing:** Custom payload injection engine

## 📋 Requirements

```txt
flask==3.0.0
flask-cors==4.0.0
requests==2.31.0
beautifulsoup4==4.12.0
```

## 🚀 Installation

1. **Clone the repository**
```bash
git clone https://github.com/nivas2104-hue/web-vulnerability-scanner.git
cd web-vulnerability-scanner
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the scanner**
```bash
python vuln_scan.py
```

4. **Access the dashboard**
Open your browser and navigate to: `http://localhost:5000`

## 📖 Usage

### ⚠️ Legal Disclaimer
**ONLY scan websites you own or have explicit written permission to test. Unauthorized vulnerability scanning is illegal and unethical.**

### Safe Testing Environments

Test the scanner on these intentionally vulnerable web applications:

- **DVWA (Damn Vulnerable Web Application)**
  - http://testphp.vulnweb.com
  
- **Altoro Mutual**
  - http://demo.testfire.net
  
- **WebGoat / OWASP Broken Web Apps**
  - http://zero.webappsecurity.com

### Scanning Process

1. Enter the target URL in the search box
2. Click **"Start Scan"**
3. Wait for the scan to complete (typically 30-60 seconds)
4. Review the detailed vulnerability report

## 📊 Output Format

### Scan Summary
```
Total Vulnerabilities: 7
├─ SQL Injections: 3 (HIGH)
├─ XSS: 3 (HIGH)
└─ CSRF: 1 (MEDIUM)
```

### Detailed Report
```
⚠️ SQL Injection - HIGH SEVERITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
URL: http://testphp.vulnweb.com/login.php
Parameter: username
Payload: ' OR '1'='1'--
Evidence: MySQL syntax error detected in response
Recommendation: Use parameterized queries
```

## 🔍 Detection Methodology

### SQL Injection
- Injects specially crafted SQL payloads into input fields
- Analyzes HTTP responses for database error messages
- Uses regex patterns to match common SQL error strings
- Tests for time-based blind SQL injection

### Cross-Site Scripting (XSS)
- Injects JavaScript payloads into form inputs
- Checks if payload is reflected in HTTP response
- Tests for script execution in various contexts
- Validates input sanitization

### CSRF
- Examines form structure for anti-CSRF tokens
- Identifies POST requests without protection
- Checks for common token naming patterns

## 📁 Project Structure

```
web-vulnerability-scanner/
├── vuln_scan.py          # Main scanner application
├── vuln_scanner.db       # SQLite database (auto-generated)
├── README.md             # Project documentation
```

## 🎓 Learning Outcomes

This project demonstrates:
- Understanding of OWASP Top 10 vulnerabilities
- Web application security testing methodology
- Python web scraping and HTTP requests
- Flask web framework development
- Database design and SQL operations
- Security-focused software development

## 🔒 Security Best Practices

This scanner is built for **educational and authorized testing only**. Key principles:
- Never scan production systems without permission
- Always obtain written authorization
- Follow responsible disclosure practices
- Respect rate limits and avoid DoS conditions
- Store results securely





---

**Then tell me: DONE or need changes?** 🚀
