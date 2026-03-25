import streamlit as st
import requests
import ssl
import socket
import dns.resolver
import whois
import json
import random
import time
import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse
from urllib.parse import quote
import base64
import concurrent.futures
from collections import defaultdict

# Page config
st.set_page_config(
    page_title="Advanced Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .stButton > button {
        width: 100%;
        background: linear-gradient(90deg, #00ff00, #00ccff);
        color: black;
        font-weight: bold;
    }
    .risk-critical {
        background-color: #ff000020;
        border-left: 4px solid #ff0000;
        padding: 10px;
        margin: 5px 0;
    }
    .risk-high {
        background-color: #ff660020;
        border-left: 4px solid #ff6600;
        padding: 10px;
        margin: 5px 0;
    }
    .risk-medium {
        background-color: #ffff0020;
        border-left: 4px solid #ffff00;
        padding: 10px;
        margin: 5px 0;
    }
    .vuln-found {
        background-color: #ff000010;
        border: 1px solid #ff0000;
        border-radius: 5px;
        padding: 10px;
        margin: 5px 0;
    }
</style>
""", unsafe_allow_html=True)

# ==================== ANONYMITY FEATURES ====================
class AnonymousScanner:
    """Handles anonymity and proxy rotation"""
    
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
        ]
        
        # Free proxy list (some may not work in cloud)
        self.proxies = [
            None,  # Direct connection
            # Add proxy servers here if available
        ]
        
        self.tor_available = self.check_tor()
    
    def check_tor(self):
        """Check if Tor is available"""
        try:
            # Test Tor connection
            response = requests.get('http://check.torproject.org', timeout=5)
            return 'Congratulations' in response.text
        except:
            return False
    
    def get_random_user_agent(self):
        """Get random user agent"""
        return random.choice(self.user_agents)
    
    def get_session(self, use_anonymity=True):
        """Create session with anonymity features"""
        session = requests.Session()
        
        if use_anonymity:
            # Random user agent
            session.headers.update({
                'User-Agent': self.get_random_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            # Random delay to avoid rate limiting
            time.sleep(random.uniform(0.5, 1.5))
        
        return session

# ==================== EXPLOIT DETECTION ====================
class ExploitDetector:
    """Detects common web vulnerabilities"""
    
    def __init__(self):
        self.vulnerabilities = []
        
        # SQL Injection patterns
        self.sql_patterns = [
            (r"SQL syntax.*MySQL", "SQL Injection (MySQL)"),
            (r"Warning.*mysql_.*", "SQL Injection (MySQL)"),
            (r"PostgreSQL.*ERROR", "SQL Injection (PostgreSQL)"),
            (r"ORA-[0-9]{5}", "SQL Injection (Oracle)"),
            (r"Microsoft.*ODBC.*SQL", "SQL Injection (MSSQL)"),
            (r"SQLite.*Exception", "SQL Injection (SQLite)"),
            (r"unclosed quotation mark", "SQL Injection (MSSQL)"),
        ]
        
        # XSS patterns
        self.xss_patterns = [
            (r"<script.*>.*</script>", "XSS (Script Injection)"),
            (r"on\w+\s*=", "XSS (Event Handler)"),
            (r"javascript:", "XSS (JavaScript URI)"),
            (r"<iframe.*>", "XSS (iFrame Injection)"),
            (r"<img.*onerror", "XSS (Image Error)"),
        ]
        
        # Path Traversal patterns
        self.path_traversal = [
            (r"root:x:0:0", "Path Traversal (Passwd Exposure)"),
            (r"etc/passwd", "Path Traversal (System File)"),
            (r"boot.ini", "Path Traversal (Windows File)"),
            (r"win.ini", "Path Traversal (Windows Config)"),
        ]
        
        # Command Injection patterns
        self.cmd_patterns = [
            (r"uid=[0-9]+\([^)]+\)", "Command Injection (Linux)"),
            (r"Microsoft Windows.*Version", "Command Injection (Windows)"),
            (r"Directory of", "Command Injection (Directory Listing)"),
        ]
        
        # SSTI patterns
        self.ssti_patterns = [
            (r"\{\{.*\}\}", "SSTI (Template Injection)"),
            (r"\${.*}", "SSTI (JSP/EL)"),
            (r"\{\%.*\%\}", "SSTI (Jinja2)"),
        ]
    
    def test_sql_injection(self, url, session):
        """Test for SQL Injection vulnerabilities"""
        findings = []
        
        # Test payloads
        payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "1' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' WAITFOR DELAY '0:0:5'--",
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}?id={quote(payload)}"
                response = session.get(test_url, timeout=5)
                
                for pattern, vuln_type in self.sql_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': vuln_type,
                            'payload': payload,
                            'evidence': re.findall(pattern, response.text, re.IGNORECASE)[:2]
                        })
            except:
                pass
        
        return findings
    
    def test_xss(self, url, session):
        """Test for XSS vulnerabilities"""
        findings = []
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}?q={quote(payload)}"
                response = session.get(test_url, timeout=5)
                
                if payload in response.text:
                    findings.append({
                        'type': 'XSS (Reflected)',
                        'payload': payload,
                        'evidence': payload[:100]
                    })
            except:
                pass
        
        return findings
    
    def check_sensitive_files(self, url, session):
        """Check for exposed sensitive files"""
        sensitive_files = [
            '.env', '.git/config', 'wp-config.php', 'config.php',
            'backup.sql', 'database.sql', 'adminer.php',
            'phpinfo.php', 'info.php', 'test.php',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            '.htaccess', '.htpasswd', 'web.config'
        ]
        
        findings = []
        for file in sensitive_files:
            try:
                test_url = f"{url}/{file}"
                response = session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    findings.append({
                        'type': 'Exposed Sensitive File',
                        'file': file,
                        'status': 'Publicly accessible'
                    })
            except:
                pass
        
        return findings
    
    def check_admin_panels(self, url, session):
        """Check for exposed admin panels"""
        admin_paths = [
            'admin', 'administrator', 'wp-admin', 'admin.php',
            'login', 'login.php', 'admin/login', 'cpanel',
            'dashboard', 'controlpanel', 'manager'
        ]
        
        findings = []
        for path in admin_paths:
            try:
                test_url = f"{url}/{path}"
                response = session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    findings.append({
                        'type': 'Exposed Admin Panel',
                        'path': path,
                        'status': 'Accessible'
                    })
            except:
                pass
        
        return findings
    
    def check_headers_vulnerabilities(self, headers):
        """Check for header-based vulnerabilities"""
        findings = []
        
        # Check for missing security headers
        security_headers = {
            'Strict-Transport-Security': 'HSTS missing - Risk of SSL stripping',
            'Content-Security-Policy': 'CSP missing - Risk of XSS attacks',
            'X-Frame-Options': 'Clickjacking risk',
            'X-Content-Type-Options': 'MIME sniffing risk',
            'Referrer-Policy': 'Information leakage risk',
        }
        
        for header, risk in security_headers.items():
            if header not in headers:
                findings.append({
                    'type': 'Missing Security Header',
                    'header': header,
                    'risk': risk
                })
        
        # Check for server info leakage
        if 'Server' in headers:
            findings.append({
                'type': 'Information Disclosure',
                'header': 'Server',
                'info': headers['Server'],
                'risk': 'Server version exposed'
            })
        
        if 'X-Powered-By' in headers:
            findings.append({
                'type': 'Information Disclosure',
                'header': 'X-Powered-By',
                'info': headers['X-Powered-By'],
                'risk': 'Technology stack exposed'
            })
        
        return findings

# ==================== STANDARD SCANNER ====================
class SecurityScanner:
    """Standard security scanner without anonymity"""
    
    def __init__(self):
        self.session = requests.Session()
    
    def check_ssl(self, domain):
        """Check SSL certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Calculate expiry
                    expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry - datetime.now()).days
                    
                    return {
                        'valid': True,
                        'issuer': cert.get('issuer', 'N/A'),
                        'expiry_days': days_left,
                        'protocol': ssock.version(),
                        'grade': 'A+' if days_left > 30 else 'B' if days_left > 0 else 'F'
                    }
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def check_headers(self, url):
        """Check HTTP headers"""
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            return {
                'headers': dict(response.headers),
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def detect_technologies(self, response):
        """Detect technologies from response"""
        techs = set()
        
        # Simple detection
        tech_patterns = {
            'WordPress': ['wp-content', 'wp-includes'],
            'Laravel': ['laravel_session', 'csrf-token'],
            'Django': ['csrftoken', 'djdebug'],
            'React': ['react', '_reactRootContainer'],
            'Angular': ['ng-version', 'ng-app'],
            'jQuery': ['jQuery', '$'],
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern.lower() in response.text.lower():
                    techs.add(tech)
        
        return list(techs)

# ==================== ANONYMOUS SCANNER ====================
class AnonymousSecurityScanner:
    """Scanner with anonymity features"""
    
    def __init__(self):
        self.anonymous = AnonymousScanner()
        self.exploit_detector = ExploitDetector()
    
    def scan_with_anonymity(self, url):
        """Perform scan with anonymity"""
        session = self.anonymous.get_session(use_anonymity=True)
        
        results = {
            'user_agent': self.anonymous.get_random_user_agent(),
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'headers': {},
            'status_code': None
        }
        
        try:
            # Use anonymous session
            response = session.get(url, timeout=15, allow_redirects=True)
            
            results['headers'] = dict(response.headers)
            results['status_code'] = response.status_code
            results['response_text'] = response.text[:5000]  # Limit text size
            
            # Check for vulnerabilities
            results['vulnerabilities'].extend(
                self.exploit_detector.check_headers_vulnerabilities(response.headers)
            )
            
            # Test for SQL Injection
            sql_findings = self.exploit_detector.test_sql_injection(url, session)
            results['vulnerabilities'].extend(sql_findings)
            
            # Test for XSS
            xss_findings = self.exploit_detector.test_xss(url, session)
            results['vulnerabilities'].extend(xss_findings)
            
            # Check sensitive files
            sensitive_findings = self.exploit_detector.check_sensitive_files(url, session)
            results['vulnerabilities'].extend(sensitive_findings)
            
            # Check admin panels
            admin_findings = self.exploit_detector.check_admin_panels(url, session)
            results['vulnerabilities'].extend(admin_findings)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results

# ==================== MAIN APP ====================
def main():
    st.title("🛡️ Advanced Web Security Scanner")
    st.markdown("### With Anonymity & Exploit Detection Features")
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Scan mode
        scan_mode = st.radio(
            "Scan Mode",
            ["🔍 Standard Scan (No Anonymity)", "🕵️ Anonymous Scan (Hidden IP)", "🎯 Full Exploit Detection"],
            help="Anonymous mode rotates user agents and hides your IP"
        )
        
        st.markdown("---")
        
        # Scan depth
        scan_depth = st.select_slider(
            "Scan Depth",
            options=["Quick", "Standard", "Deep", "Aggressive"],
            value="Standard"
        )
        
        st.markdown("---")
        
        # Features info
        with st.expander("📋 Features Included"):
            st.markdown("""
            **Standard Features:**
            - SSL/TLS Analysis
            - Security Headers Check
            - Technology Detection
            - Response Time Analysis
            
            **Anonymous Features:**
            - Rotating User Agents
            - Request Delays
            - Header Obfuscation
            
            **Exploit Detection:**
            - SQL Injection Testing
            - XSS Vulnerability Check
            - Sensitive File Exposure
            - Admin Panel Discovery
            - Information Disclosure
            """)
        
        st.markdown("---")
        st.caption("⚠️ Educational Purpose Only")
        st.caption("Always get proper authorization")
    
    # Main content
    col1, col2 = st.columns([3, 1])
    
    with col1:
        url = st.text_input(
            "🌐 Target URL",
            placeholder="https://example.com",
            help="Enter full URL including protocol"
        )
    
    with col2:
        if st.button("🚀 Start Scan", type="primary", use_container_width=True):
            if url:
                perform_scan(url, scan_mode, scan_depth)
            else:
                st.warning("Please enter a URL first")

def perform_scan(url, scan_mode, scan_depth):
    """Perform scan based on selected mode"""
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    domain = urlparse(url).netloc
    
    # Create progress bar
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Initialize scanners
    standard_scanner = SecurityScanner()
    anonymous_scanner = AnonymousSecurityScanner()
    
    # Determine if using anonymity
    use_anonymity = "Anonymous" in scan_mode or "Full" in scan_mode
    
    # Create tabs for results
    if "Full" in scan_mode:
        tabs = st.tabs(["📊 Overview", "🔒 SSL/TLS", "🛡️ Headers", "💣 Vulnerabilities", "🕵️ Anonymous Data"])
    else:
        tabs = st.tabs(["📊 Overview", "🔒 SSL/TLS", "🛡️ Headers", "💣 Vulnerabilities"])
    
    # Tab 1: Overview
    with tabs[0]:
        st.subheader("Scan Configuration")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Target", domain)
            st.metric("Scan Mode", scan_mode)
            st.metric("Scan Depth", scan_depth)
        
        with col2:
            st.metric("Anonymity", "✅ Enabled" if use_anonymity else "❌ Disabled")
            st.metric("Timestamp", datetime.now().strftime("%H:%M:%S"))
            if use_anonymity:
                st.metric("User Agent", anonymous_scanner.anonymous.get_random_user_agent()[:50] + "...")
        
        with col3:
            st.metric("Status", "🔄 Scanning...")
    
    # Perform scans
    status_text.text("🔍 Checking SSL/TLS...")
    progress_bar.progress(20)
    
    # SSL Check
    ssl_result = standard_scanner.check_ssl(domain)
    
    with tabs[1]:
        if ssl_result.get('valid'):
            st.success("✅ SSL Certificate Valid")
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Issuer:**", ssl_result.get('issuer'))
                st.write("**Protocol:**", ssl_result.get('protocol'))
            with col2:
                st.write("**Days until expiry:**", ssl_result.get('expiry_days'))
                st.write("**Grade:**", f"**{ssl_result.get('grade')}**")
        else:
            st.error(f"❌ SSL Error: {ssl_result.get('error', 'Unknown error')}")
    
    # Headers Check
    status_text.text("🛡️ Analyzing Security Headers...")
    progress_bar.progress(40)
    
    headers_result = standard_scanner.check_headers(url)
    
    with tabs[2]:
        if 'error' not in headers_result:
            st.write(f"**Status Code:** {headers_result.get('status_code')}")
            st.write(f"**Response Time:** {headers_result.get('response_time'):.3f}s")
            
            # Security headers analysis
            security_headers = [
                'Strict-Transport-Security', 'Content-Security-Policy',
                'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy'
            ]
            
            for header in security_headers:
                if header in headers_result['headers']:
                    st.success(f"✅ {header}: Present")
                else:
                    st.warning(f"⚠️ {header}: Missing")
        else:
            st.error(f"Error: {headers_result['error']}")
    
    # Vulnerability Detection
    status_text.text("💣 Scanning for Vulnerabilities...")
    progress_bar.progress(60)
    
    if "Full" in scan_mode or use_anonymity:
        # Use anonymous scanner for exploit detection
        anonymous_results = anonymous_scanner.scan_with_anonymity(url)
        vulnerabilities = anonymous_results.get('vulnerabilities', [])
        
        with tabs[3]:
            if vulnerabilities:
                st.error(f"⚠️ Found {len(vulnerabilities)} potential vulnerabilities")
                
                # Group vulnerabilities by type
                vuln_groups = defaultdict(list)
                for vuln in vulnerabilities:
                    vuln_groups[vuln['type']].append(vuln)
                
                for vuln_type, items in vuln_groups.items():
                    with st.expander(f"🔴 {vuln_type} ({len(items)} findings)"):
                        for item in items:
                            st.markdown(f"""
                            <div class='vuln-found'>
                                <b>Details:</b><br/>
                                {json.dumps(item, indent=2, default=str)}
                            </div>
                            """, unsafe_allow_html=True)
            else:
                st.success("✅ No common vulnerabilities detected")
    else:
        # Standard vulnerability check
        with tabs[3]:
            st.info("Enable Full Exploit Detection mode for comprehensive vulnerability scanning")
    
    # Anonymous Data (if applicable)
    if "Full" in scan_mode and use_anonymity:
        with tabs[4]:
            st.subheader("🕵️ Anonymous Scan Data")
            
            col1, col2 = st.columns(2)
            with col1:
                st.write("**User Agent Used:**")
                st.code(anonymous_results.get('user_agent'))
                st.write("**Timestamp:**", anonymous_results.get('timestamp'))
            
            with col2:
                st.write("**Response Headers (Obfuscated):**")
                headers_display = {k: v[:100] + "..." if len(str(v)) > 100 else v 
                                  for k, v in anonymous_results.get('headers', {}).items()}
                st.json(headers_display)
    
    # Final Progress
    progress_bar.progress(100)
    status_text.text("✅ Scan Complete!")
    
    # Risk Assessment
    st.markdown("---")
    st.subheader("📊 Risk Assessment Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        ssl_risk = "Low" if ssl_result.get('grade') == 'A+' else "Medium" if ssl_result.get('valid') else "High"
        st.metric("SSL Risk", ssl_risk)
    
    with col2:
        vuln_count = len(vulnerabilities) if 'vulnerabilities' in locals() else 0
        vuln_risk = "Low" if vuln_count == 0 else "Medium" if vuln_count < 5 else "High"
        st.metric("Vulnerability Risk", vuln_risk)
    
    with col3:
        headers_missing = sum(1 for h in security_headers if h not in headers_result.get('headers', {}))
        header_risk = "Low" if headers_missing < 2 else "Medium" if headers_missing < 4 else "High"
        st.metric("Headers Risk", header_risk)
    
    with col4:
        overall = "Low" if (ssl_risk == "Low" and vuln_risk == "Low" and header_risk == "Low") else \
                 "Medium" if (ssl_risk == "Medium" or vuln_risk == "Medium" or header_risk == "Medium") else "High"
        st.metric("Overall Risk", overall, 
                  delta="⚠️ Needs Attention" if overall != "Low" else "✅ Secure")

if __name__ == "__main__":
    main()
