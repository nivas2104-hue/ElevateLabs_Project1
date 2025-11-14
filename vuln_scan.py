from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import re
import sqlite3
from datetime import datetime
from urllib.parse import urljoin, urlparse
import time

app = Flask(__name__)
CORS(app)

# ===== SQL INJECTION PAYLOADS =====
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "admin'--",
    "' OR 1=1--",
    "') OR ('1'='1",
    "1' OR '1' = '1",
    "' UNION SELECT NULL--",
    "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055"
]

# ===== XSS PAYLOADS =====
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<body onload=alert('XSS')>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<input type='text' value='\" onmouseover=\"alert('XSS')' />"
]

# ===== SQL ERROR PATTERNS =====
SQL_ERRORS = [
    "SQL syntax.*MySQL",
    "Warning.*mysql_.*",
    "valid MySQL result",
    "MySqlClient\\.",
    "PostgreSQL.*ERROR",
    "Warning.*\\Wpg_.*",
    "valid PostgreSQL result",
    "Npgsql\\.",
    "Microsoft SQL Native Client error",
    "ODBC SQL Server Driver",
    "SQLServer JDBC Driver",
    "Oracle error",
    "ORA-[0-9][0-9][0-9][0-9]",
    "quoted string not properly terminated",
    "SQL command not properly ended",
    "unclosed quotation mark"
]

# ===== DATABASE SETUP =====
def init_db():
    conn = sqlite3.connect('vuln_scanner.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  target_url TEXT,
                  total_vulns INTEGER,
                  sqli_count INTEGER,
                  xss_count INTEGER,
                  csrf_count INTEGER,
                  scan_duration REAL,
                  timestamp TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id INTEGER,
                  vuln_type TEXT,
                  severity TEXT,
                  url TEXT,
                  parameter TEXT,
                  payload TEXT,
                  evidence TEXT,
                  FOREIGN KEY (scan_id) REFERENCES scans (id))''')
    conn.commit()
    conn.close()

init_db()

# ===== HELPER FUNCTIONS =====
def get_forms(url):
    """Extract all forms from a webpage"""
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except Exception as e:
        print(f"Error getting forms: {e}")
        return []

def get_form_details(form):
    """Extract form details including action, method, and inputs"""
    details = {}
    action = form.attrs.get('action', '').lower()
    method = form.attrs.get('method', 'get').lower()
    inputs = []
    
    for input_tag in form.find_all('input'):
        input_type = input_tag.attrs.get('type', 'text')
        input_name = input_tag.attrs.get('name')
        input_value = input_tag.attrs.get('value', '')
        inputs.append({
            'type': input_type,
            'name': input_name,
            'value': input_value
        })
    
    for select in form.find_all('select'):
        select_name = select.attrs.get('name')
        inputs.append({
            'type': 'select',
            'name': select_name,
            'value': ''
        })
    
    for textarea in form.find_all('textarea'):
        textarea_name = textarea.attrs.get('name')
        inputs.append({
            'type': 'textarea',
            'name': textarea_name,
            'value': ''
        })
    
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def check_sql_injection(url, form_details):
    """Test for SQL injection vulnerabilities"""
    vulnerabilities = []
    target_url = urljoin(url, form_details['action'])
    
    for payload in SQL_PAYLOADS:
        data = {}
        for input_field in form_details['inputs']:
            if input_field['type'] == 'submit':
                data[input_field['name']] = input_field.get('value', 'submit')
            else:
                data[input_field['name']] = payload
        
        try:
            if form_details['method'] == 'post':
                response = requests.post(target_url, data=data, timeout=10)
            else:
                response = requests.get(target_url, params=data, timeout=10)
            
            # Check for SQL errors in response
            for error_pattern in SQL_ERRORS:
                if re.search(error_pattern, response.text, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'HIGH',
                        'url': target_url,
                        'parameter': ', '.join([i['name'] for i in form_details['inputs'] if i['name']]),
                        'payload': payload,
                        'evidence': f"SQL error pattern detected: {error_pattern}"
                    })
                    break
            
            # Check for significant response length difference (blind SQLi indicator)
            if len(response.text) > 10000 or "login success" in response.text.lower():
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'HIGH',
                    'url': target_url,
                    'parameter': ', '.join([i['name'] for i in form_details['inputs'] if i['name']]),
                    'payload': payload,
                    'evidence': 'Unusual response detected (possible successful injection)'
                })
                break
                
        except Exception as e:
            continue
    
    return vulnerabilities

def check_xss(url, form_details):
    """Test for XSS vulnerabilities"""
    vulnerabilities = []
    target_url = urljoin(url, form_details['action'])
    
    for payload in XSS_PAYLOADS:
        data = {}
        for input_field in form_details['inputs']:
            if input_field['type'] == 'submit':
                data[input_field['name']] = input_field.get('value', 'submit')
            else:
                data[input_field['name']] = payload
        
        try:
            if form_details['method'] == 'post':
                response = requests.post(target_url, data=data, timeout=10)
            else:
                response = requests.get(target_url, params=data, timeout=10)
            
            # Check if payload is reflected in response
            if payload in response.text:
                vulnerabilities.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'HIGH',
                    'url': target_url,
                    'parameter': ', '.join([i['name'] for i in form_details['inputs'] if i['name']]),
                    'payload': payload,
                    'evidence': 'Payload reflected in response without sanitization'
                })
                break
                
        except Exception as e:
            continue
    
    return vulnerabilities

def check_csrf(url, form_details):
    """Check for CSRF protection"""
    vulnerabilities = []
    
    # Check if form has CSRF token
    has_csrf_token = False
    for input_field in form_details['inputs']:
        if input_field['name'] and any(token in input_field['name'].lower() 
                                       for token in ['csrf', 'token', '_token', 'authenticity']):
            has_csrf_token = True
            break
    
    if not has_csrf_token and form_details['method'] == 'post':
        vulnerabilities.append({
            'type': 'CSRF (Cross-Site Request Forgery)',
            'severity': 'MEDIUM',
            'url': urljoin(url, form_details['action']),
            'parameter': 'Form',
            'payload': 'N/A',
            'evidence': 'No CSRF token found in POST form'
        })
    
    return vulnerabilities

def save_scan_results(target_url, vulnerabilities, scan_duration):
    """Save scan results to database"""
    try:
        conn = sqlite3.connect('vuln_scanner.db')
        c = conn.cursor()
        
        sqli_count = sum(1 for v in vulnerabilities if v['type'] == 'SQL Injection')
        xss_count = sum(1 for v in vulnerabilities if 'XSS' in v['type'])
        csrf_count = sum(1 for v in vulnerabilities if 'CSRF' in v['type'])
        
        c.execute('''INSERT INTO scans 
                     (target_url, total_vulns, sqli_count, xss_count, csrf_count, scan_duration, timestamp)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (target_url, len(vulnerabilities), sqli_count, xss_count, csrf_count, 
                   scan_duration, datetime.now().isoformat()))
        
        scan_id = c.lastrowid
        
        for vuln in vulnerabilities:
            c.execute('''INSERT INTO vulnerabilities
                         (scan_id, vuln_type, severity, url, parameter, payload, evidence)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (scan_id, vuln['type'], vuln['severity'], vuln['url'],
                       vuln['parameter'], vuln['payload'], vuln['evidence']))
        
        conn.commit()
        conn.close()
        return scan_id
    except Exception as e:
        print(f"Database error: {e}")
        return None

# ===== WEB INTERFACE =====
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Web Vulnerability Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .scan-box {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }
        .input-group {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
        }
        input[type="text"] {
            flex: 1;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: border 0.3s;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            padding: 15px 40px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
        }
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        .status {
            text-align: center;
            padding: 20px;
            font-size: 18px;
            color: #666;
        }
        .results {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .stat-card.total { background: #e3f2fd; border-left: 5px solid #2196f3; }
        .stat-card.high { background: #ffebee; border-left: 5px solid #f44336; }
        .stat-card.medium { background: #fff3e0; border-left: 5px solid #ff9800; }
        .stat-card.low { background: #e8f5e9; border-left: 5px solid #4caf50; }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-label {
            color: #666;
            font-size: 0.9em;
        }
        .vuln-list {
            margin-top: 20px;
        }
        .vuln-item {
            background: #f5f5f5;
            border-left: 5px solid #f44336;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }
        .vuln-item.medium { border-left-color: #ff9800; }
        .vuln-item.low { border-left-color: #4caf50; }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .vuln-type {
            font-size: 1.2em;
            font-weight: bold;
            color: #333;
        }
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }
        .severity-badge.HIGH { background: #f44336; }
        .severity-badge.MEDIUM { background: #ff9800; }
        .severity-badge.LOW { background: #4caf50; }
        .vuln-details {
            color: #666;
            line-height: 1.6;
        }
        .vuln-details strong {
            color: #333;
        }
        code {
            background: #333;
            color: #0f0;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .history {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        .history-item {
            padding: 15px;
            background: #f9f9f9;
            border-radius: 8px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .warning-box {
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .warning-box strong {
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Web Vulnerability Scanner</h1>
            <p>Automated OWASP Top 10 Security Testing</p>
        </div>

        <div class="scan-box">
            <div class="warning-box">
                <strong>⚠️ Legal Warning:</strong> Only scan websites you own or have explicit permission to test.
                Unauthorized scanning is illegal and unethical.
            </div>
            
            <div class="input-group">
                <input type="text" id="targetUrl" placeholder="Enter target URL (e.g., http://testphp.vulnweb.com)">
                <button onclick="startScan()" id="scanBtn">Start Scan</button>
            </div>
            
            <div id="status" class="status"></div>
        </div>

        <div id="results" style="display: none;"></div>
        
        <div class="history">
            <h2>📜 Scan History</h2>
            <div id="history"></div>
        </div>
    </div>

    <script>
        async function startScan() {
            const url = document.getElementById('targetUrl').value.trim();
            if (!url) {
                alert('Please enter a target URL');
                return;
            }

            const scanBtn = document.getElementById('scanBtn');
            const status = document.getElementById('status');
            
            scanBtn.disabled = true;
            status.innerHTML = '<div class="loading"></div> Scanning in progress... This may take a few minutes.';
            document.getElementById('results').style.display = 'none';

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });

                const data = await response.json();
                
                if (data.success) {
                    displayResults(data);
                    loadHistory();
                } else {
                    status.innerHTML = '❌ Error: ' + data.error;
                }
            } catch (error) {
                status.innerHTML = '❌ Scan failed: ' + error.message;
            } finally {
                scanBtn.disabled = false;
            }
        }

        function displayResults(data) {
            const resultsDiv = document.getElementById('results');
            const status = document.getElementById('status');
            
            status.innerHTML = '✅ Scan completed in ' + data.scan_duration.toFixed(2) + ' seconds';
            
            let html = `
                <div class="summary">
                    <div class="stat-card total">
                        <div class="stat-number">${data.total_vulnerabilities}</div>
                        <div class="stat-label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card high">
                        <div class="stat-number">${data.sqli_count}</div>
                        <div class="stat-label">SQL Injections</div>
                    </div>
                    <div class="stat-card high">
                        <div class="stat-number">${data.xss_count}</div>
                        <div class="stat-label">XSS Vulnerabilities</div>
                    </div>
                    <div class="stat-card medium">
                        <div class="stat-number">${data.csrf_count}</div>
                        <div class="stat-label">CSRF Issues</div>
                    </div>
                </div>

                <h2>🔎 Vulnerability Details</h2>
            `;

            if (data.vulnerabilities.length === 0) {
                html += '<p style="text-align: center; color: #4caf50; font-size: 1.2em; padding: 20px;">✅ No vulnerabilities detected! The target appears secure.</p>';
            } else {
                html += '<div class="vuln-list">';
                data.vulnerabilities.forEach(vuln => {
                    html += `
                        <div class="vuln-item ${vuln.severity.toLowerCase()}">
                            <div class="vuln-header">
                                <div class="vuln-type">${vuln.type}</div>
                                <span class="severity-badge ${vuln.severity}">${vuln.severity}</span>
                            </div>
                            <div class="vuln-details">
                                <p><strong>URL:</strong> ${vuln.url}</p>
                                <p><strong>Parameter:</strong> ${vuln.parameter}</p>
                                <p><strong>Payload:</strong> <code>${vuln.payload}</code></p>
                                <p><strong>Evidence:</strong> ${vuln.evidence}</p>
                            </div>
                        </div>
                    `;
                });
                html += '</div>';
            }

            resultsDiv.innerHTML = html;
            resultsDiv.style.display = 'block';
        }

        async function loadHistory() {
            try {
                const response = await fetch('/api/history');
                const data = await response.json();
                
                let html = '';
                data.forEach(scan => {
                    html += `
                        <div class="history-item">
                            <div>
                                <strong>${scan.target_url}</strong><br>
                                <small style="color: #999;">${scan.timestamp}</small>
                            </div>
                            <div style="text-align: right;">
                                <strong style="color: ${scan.total_vulns > 0 ? '#f44336' : '#4caf50'}">
                                    ${scan.total_vulns} vulnerabilities
                                </strong><br>
                                <small>${scan.scan_duration.toFixed(2)}s</small>
                            </div>
                        </div>
                    `;
                });
                
                document.getElementById('history').innerHTML = html || '<p style="text-align: center; color: #999;">No scan history yet</p>';
            } catch (error) {
                console.error('Error loading history:', error);
            }
        }

        // Load history on page load
        loadHistory();
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan', methods=['POST'])
def scan():
    """Main scanning endpoint"""
    try:
        data = request.json
        target_url = data.get('url', '').strip()
        
        if not target_url:
            return jsonify({'success': False, 'error': 'No URL provided'}), 400
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        start_time = time.time()
        all_vulnerabilities = []
        
        # Get all forms from the target
        forms = get_forms(target_url)
        
        if not forms:
            return jsonify({
                'success': True,
                'total_vulnerabilities': 0,
                'sqli_count': 0,
                'xss_count': 0,
                'csrf_count': 0,
                'vulnerabilities': [],
                'scan_duration': time.time() - start_time,
                'message': 'No forms found on the target page'
            })
        
        # Test each form
        for form in forms:
            form_details = get_form_details(form)
            
            # Check for SQL Injection
            sqli_vulns = check_sql_injection(target_url, form_details)
            all_vulnerabilities.extend(sqli_vulns)
            
            # Check for XSS
            xss_vulns = check_xss(target_url, form_details)
            all_vulnerabilities.extend(xss_vulns)
            
            # Check for CSRF
            csrf_vulns = check_csrf(target_url, form_details)
            all_vulnerabilities.extend(csrf_vulns)
        
        scan_duration = time.time() - start_time
        
        # Save to database
        save_scan_results(target_url, all_vulnerabilities, scan_duration)
        
        # Count by type
        sqli_count = sum(1 for v in all_vulnerabilities if v['type'] == 'SQL Injection')
        xss_count = sum(1 for v in all_vulnerabilities if 'XSS' in v['type'])
        csrf_count = sum(1 for v in all_vulnerabilities if 'CSRF' in v['type'])
        
        return jsonify({
            'success': True,
            'target_url': target_url,
            'total_vulnerabilities': len(all_vulnerabilities),
            'sqli_count': sqli_count,
            'xss_count': xss_count,
            'csrf_count': csrf_count,
            'vulnerabilities': all_vulnerabilities,
            'scan_duration': scan_duration
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get scan history"""
    try:
        conn = sqlite3.connect('vuln_scanner.db')
        c = conn.cursor()
        c.execute('''SELECT target_url, total_vulns, sqli_count, xss_count, 
                     csrf_count, scan_duration, timestamp 
                     FROM scans ORDER BY id DESC LIMIT 10''')
        rows = c.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                'target_url': row[0],
                'total_vulns': row[1],
                'sqli_count': row[2],
                'xss_count': row[3],
                'csrf_count': row[4],
                'scan_duration': row[5],
                'timestamp': row[6]
            })
        
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("=" * 60)
    print("🔍 Web Vulnerability Scanner Starting...")
    print("=" * 60)
    print("⚠️  LEGAL WARNING: Only scan sites you own or have permission!")
    print("=" * 60)
    print("📝 Test on these safe, intentionally vulnerable sites:")
    print("   • http://testphp.vulnweb.com")
    print("   • http://demo.testfire.net")
    print("   • http://zero.webappsecurity.com")
    print("=" * 60)
    print("🌐 Scanner running at: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, port=5000)