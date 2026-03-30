import streamlit as st
import requests
import re
import random
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

st.set_page_config(page_title="🧠 Ultra AI Scanner", layout="wide")

MAX_THREADS = 8
CRAWL_LIMIT = 20

USER_AGENTS = [
    "Mozilla/5.0",
    "Chrome/120.0",
]

PARAMS = ["id", "q", "search", "page"]

# ================= FILTER =================
def is_valid_target(url):
    blocked = (".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".ico")
    return not url.lower().endswith(blocked)

# ================= CRAWLER =================
def crawl(url):
    visited = set()
    to_visit = [url]

    base = urlparse(url).netloc

    while to_visit and len(visited) < CRAWL_LIMIT:
        u = to_visit.pop(0)

        if u in visited:
            continue

        visited.add(u)

        try:
            r = requests.get(u, timeout=5)
            links = re.findall(r'href=["\'](.*?)["\']', r.text)

            for link in links:
                full = urljoin(u, link)

                if urlparse(full).netloc == base and is_valid_target(full):
                    to_visit.append(full)
        except:
            pass

    return list(visited)

# ================= PARAM DISCOVERY =================
def discover_params(url):
    found = []

    for p in PARAMS:
        test_url = f"{url}?{p}=test"
        try:
            r = requests.get(test_url, timeout=5)
            if "test" in r.text:
                found.append(p)
        except:
            pass

    return found

# ================= AI ANALYSIS =================
def analyze(base, test):
    score = 0
    reasons = []

    # panjang berubah
    if abs(len(test.text) - len(base.text)) > 100:
        score += 2
        reasons.append("Response size changed")

    # status berubah
    if base.status_code != test.status_code:
        score += 2
        reasons.append("Status changed")

    # delay
    if test.elapsed.total_seconds() > base.elapsed.total_seconds() * 2:
        score += 2
        reasons.append("Delay anomaly")

    # error nyata
    errors = ["sql syntax", "mysql", "error in your query"]
    for e in errors:
        if e in test.text.lower():
            score += 3
            reasons.append("SQL error detected")

    return score, reasons

# ================= SCAN =================
def scan(url):
    if not is_valid_target(url):
        return []

    session = requests.Session()
    session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    findings = []

    try:
        base = session.get(url, timeout=5)

        params = discover_params(url)
        if not params:
            params = ["q"]

        payloads = [
            "' OR 1=1 --",
            "<script>alert(1)</script>"
        ]

        for param in params:
            for p in payloads:
                test_url = f"{url}?{param}={quote(p)}"

                try:
                    r = session.get(test_url, timeout=5)

                    score, reasons = analyze(base, r)

                    if score >= 3:
                        findings.append({
                            "url": url,
                            "param": param,
                            "payload": p,
                            "score": score,
                            "reasons": reasons
                        })

                except:
                    pass

    except:
        pass

    return findings

# ================= MAIN =================
def main():
    st.title("🧠 ULTRA INTELLIGENCE SCANNER")

    target = st.text_input("Target URL")

    if st.button("🚀 Scan Ultra"):
        if not target:
            st.warning("Masukkan URL")
            return

        if not target.startswith("http"):
            target = "https://" + target

        st.write("## 🕷️ Crawling...")
        urls = crawl(target)

        st.success(f"{len(urls)} halaman valid")

        st.write("## ⚡ Smart Scanning...")

        findings = []

        progress = st.progress(0)

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [executor.submit(scan, u) for u in urls]

            for i, f in enumerate(as_completed(futures)):
                findings.extend(f.result())
                progress.progress((i + 1) / len(futures))

        st.write("## 💣 Findings")

        if findings:
            for f in findings:
                st.error(f"""
URL: {f['url']}
Param: {f['param']}
Payload: {f['payload']}
Score: {f['score']}
Reason: {", ".join(f['reasons'])}
                """)
        else:
            st.success("Tidak ditemukan vulnerability signifikan 🎉")

if __name__ == "__main__":
    main()
