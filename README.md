# Cyber Threat Intelligence (CTI) Dashboard

A real-time threat intelligence platform that integrates with VirusTotal and AbuseIPDB APIs to verify and analyze Indicators of Compromise (IOCs).

## Features
- Real-time IP and domain reputation checking
- Integration with VirusTotal and AbuseIPDB APIs
- Automated threat scoring (0-100 scale)
- Threat categorization (Malware, Abuse, Suspicious, Clean)
- Search history with SQLite database
- Professional web-based dashboard interface

## Technologies Used
- Python 3.x
- Flask (Web Framework)
- SQLite (Database)
- VirusTotal API v3
- AbuseIPDB API v2
- HTML/CSS/JavaScript

## Security Intelligence Features
- **IOC Verification:** Check IPs and domains against global threat databases
- **Multi-Source Analysis:** Combines data from VirusTotal and AbuseIPDB
- **Threat Scoring:** Intelligent scoring algorithm based on multiple factors
- **Historical Tracking:** Maintains search history for trend analysis

## Installation

1. Clone the repository
```bash
git clone https://github.com/nivas2104-hue/ElevateLabs_Project2.git
cd ElevateLabs_Project2
```

2. Install dependencies
```bash
pip install flask flask-cors requests
```

3. Get API Keys
- VirusTotal: https://www.virustotal.com/ (Free account)
- AbuseIPDB: https://www.abuseipdb.com/ (Free account)

4. Configure API keys
Edit `app.py` and add your API keys:
```python
VIRUSTOTAL_API_KEY = "your_virustotal_key_here"
ABUSEIPDB_API_KEY = "your_abuseipdb_key_here"
```

5. Run the application
```bash
python app.py
```

6. Open browser and go to `http://localhost:5000`

## Usage

### Basic Workflow
1. Select "IP Address" or "Domain" from dropdown
2. Enter the IOC to check
3. Click "Check Threat"
4. View comprehensive threat analysis

### Example Queries
- **Clean IP:** `8.8.8.8` (Google DNS)
- **Suspicious IP:** `185.220.101.3` (Tor exit node)
- **Domain:** `google.com` (Clean)

## API Integration

### VirusTotal
- Checks against 70+ antivirus engines
- Provides malware detection scores
- Historical analysis data

### AbuseIPDB
- Reports abuse confidence score
- Total abuse reports count
- Last reported timestamp
- Whitelisting status

## Threat Scoring Algorithm
```
Final Threat Score = MAX(VirusTotal Score, AbuseIPDB Score)

Categories:
- 0-24: Clean
- 25-49: Low Risk
- 50-74: Medium Risk (Suspicious)
- 75-100: High Risk (Malware/Abuse)
```

## Database Schema
```sql
CREATE TABLE searches (
    id INTEGER PRIMARY KEY,
    query TEXT,
    search_type TEXT,
    threat_score INTEGER,
    is_malicious INTEGER,
    vt_score INTEGER,
    abuse_score INTEGER,
    categories TEXT,
    timestamp TEXT
);
```

## Use Cases
- **SOC Operations:** Quick IOC verification for incident response
- **Threat Hunting:** Research suspicious IPs and domains
- **Security Research:** Analyze threat actor infrastructure
- **Network Monitoring:** Validate alerts from security tools


# Python
__pycache__/
*.py[cod]
*.so
*.egg
*.egg-info/
*.pyc

# Database
*.db
*.sqlite
cti_dashboard.db

# Environment
.env
venv/
env/

# API Keys (IMPORTANT!)
*API_KEY*
config.py
secrets.py

# IDE
.vscode/
.idea/
*.swp
*.swo

# Logs
*.log

# OS
.DS_Store
Thumbs.db
