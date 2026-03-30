import streamlit as st
import requests
import ssl
import socket
import json
import random
import time
import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse, quote
import base64
import concurrent.futures
from collections import defaultdict

# Safe import
try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import whois
except ImportError:
    whois = None


# ================= PAGE CONFIG =================
st.set_page_config(
    page_title="Advanced Security Scanner",
    page_icon="🛡️",
    layout="wide"
)

# ================= ANONYMITY =================
class AnonymousScanner:
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'Mozilla/5.0 (X11; Linux x86_64)',
        ]

    def get_session(self):
        session = requests.Session()
        session.headers.update({
            'User-Agent': random.choice(self.user_agents)
        })
        time.sleep(random.uniform(0.5, 1.5))
        return session


# ================= EXPLOIT DETECTOR =================
class ExploitDetector:
    def __init__(self):
        self.sql_patterns = [
            (r"SQL syntax", "SQL Injection"),
            (r"mysql_", "SQL Injection"),
        ]

    def test_sql_injection(self, url, session):
        findings = []
        payloads = ["'", "' OR 1=1 --"]

        for payload in payloads:
            try:
                r = session.get(f"{url}?id={quote(payload)}", timeout=5)
                for pattern, name in self.sql_patterns:
                    if re.search(pattern, r.text, re.IGNORECASE):
                        findings.append(name)
            except:
                pass
        return findings


# ================= STANDARD SCANNER =================
class SecurityScanner:
    def __init__(self):
        self.session = requests.Session()

    def check_ssl(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days = (expiry - datetime.now()).days
                    return {"valid": True, "days": days}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def check_headers(self, url):
        try:
            r = self.session.get(url, timeout=5)
            return dict(r.headers)
        except:
            return {}


# ================= MAIN =================
def main():
    st.title("🛡️ Web Security Scanner")

    url = st.text_input("Target URL")

    if st.button("Scan"):
        if not url:
            st.warning("Masukkan URL dulu")
            return

        if not url.startswith("http"):
            url = "https://" + url

        domain = urlparse(url).netloc

        scanner = SecurityScanner()
        anon = AnonymousScanner()
        exploit = ExploitDetector()

        session = anon.get_session()

        st.write("## 🔒 SSL Check")
        ssl_result = scanner.check_ssl(domain)
        st.write(ssl_result)

        st.write("## 🛡️ Headers")
        headers = scanner.check_headers(url)
        st.json(headers)

        st.write("## 💣 Vulnerability Scan")
        vulnerabilities = exploit.test_sql_injection(url, session)

        if vulnerabilities:
            st.error(vulnerabilities)
        else:
            st.success("Aman dari SQL Injection sederhana")

        st.write("## 🌐 Extra Info")

        # DNS check
        if dns:
            try:
                answers = dns.resolver.resolve(domain, 'A')
                ips = [str(r) for r in answers]
                st.write("IP:", ips)
            except:
                st.write("DNS lookup gagal")
        else:
            st.warning("DNS module tidak tersedia")

        # WHOIS check
        if whois:
            try:
                data = whois.whois(domain)
                st.write("WHOIS:", data.domain_name)
            except:
                st.write("WHOIS gagal")
        else:
            st.warning("WHOIS module tidak tersedia")


if __name__ == "__main__":
    main()
