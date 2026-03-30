import streamlit as st
import requests
import re
import random
from urllib.parse import urljoin, urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

st.set_page_config(page_title="🔥 Cyber Scanner", layout="wide")

MAX_THREADS = 8

COMMON_SUBDOMAINS = ["admin", "dev", "test", "api", "staging"]
COMMON_CREDS = [("admin", "admin"), ("admin", "1234"), ("test", "test")]

USER_AGENTS = [
    "Mozilla/5.0",
    "Chrome/120.0",
]

# ================= SUBDOMAIN =================
def find_subdomains(domain):
    found = []
    for sub in COMMON_SUBDOMAINS:
        url = f"http://{sub}.{domain}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 400:
                found.append(url)
        except:
            pass
    return found

# ================= CRAWLER =================
def crawl(url):
    visited = set()
    to_visit = [url]

    base = urlparse(url).netloc

    while to_visit and len(visited) < 15:
        u = to_visit.pop(0)
        if u in visited:
            continue

        visited.add(u)

        try:
            r = requests.get(u, timeout=3)
            links = re.findall(r'href=["\'](.*?)["\']', r.text)

            for link in links:
                full = urljoin(u, link)
                if urlparse(full).netloc == base:
                    to_visit.append(full)
        except:
            pass

    return list(visited)

# ================= AI DETECTION =================
def ai_score(text, delay):
    score = 0

    if "sql" in text.lower():
        score += 3
    if "<script>" in text:
        score += 2
    if delay > 2:
        score += 2

    return score

# ================= SCAN =================
def scan(url):
    session = requests.Session()
    session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    findings = []

    payloads = [
        "' OR 1=1 --",
        "<script>alert(1)</script>"
    ]

    try:
        base = session.get(url, timeout=3)
        base_time = base.elapsed.total_seconds()

        for p in payloads:
            test_url = f"{url}?q={quote(p)}"
            r = session.get(test_url, timeout=3)

            score = ai_score(r.text, r.elapsed.total_seconds())

            if score > 0:
                findings.append((url, p, score))
    except:
        pass

    return findings

# ================= LOGIN TEST =================
def test_login(url):
    results = []
    for u, p in COMMON_CREDS:
        try:
            r = requests.post(url, data={"username": u, "password": p}, timeout=3)
            if "dashboard" in r.text.lower():
                results.append((u, p))
        except:
            pass
    return results

# ================= MAIN =================
def main():
    st.title("🔥 AI Cyber Scanner LEVEL UP")

    target = st.text_input("Target URL")

    if st.button("🚀 START ATTACK (SAFE MODE)"):
        if not target:
            return

        if not target.startswith("http"):
            target = "https://" + target

        domain = urlparse(target).netloc

        st.write("## 🌐 Subdomain Scan")
        subs = find_subdomains(domain)
        st.write(subs)

        st.write("## 🕷️ Crawling")
        urls = crawl(target) + subs
        st.write(f"{len(urls)} URLs ditemukan")

        st.write("## ⚡ Scanning")

        findings = []

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as exe:
            futures = [exe.submit(scan, u) for u in urls]

            for f in as_completed(futures):
                findings.extend(f.result())

        st.write("## 💣 Vulnerabilities")
        if findings:
            for f in findings:
                st.error(f)
        else:
            st.success("Aman")

        st.write("## 🔐 Login Test (basic)")
        login_results = test_login(target)

        if login_results:
            st.error(login_results)
        else:
            st.success("Login aman")

if __name__ == "__main__":
    main()
