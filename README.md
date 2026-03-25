# 🛡️ Advanced Web Security Scanner

## Features

### 🔍 Standard Scan
- SSL/TLS Certificate Analysis
- Security Headers Check (HSTS, CSP, X-Frame-Options, etc.)
- Technology Detection
- Response Time Analysis

### 🕵️ Anonymous Scan
- Rotating User Agents
- IP Obfuscation
- Request Delays to Avoid Rate Limiting
- Header Randomization

### 💣 Exploit Detection
- SQL Injection Testing
- XSS Vulnerability Detection
- Sensitive File Exposure Check
- Admin Panel Discovery
- Information Disclosure Detection
- Path Traversal Testing

## Deployment to Streamlit Cloud

1. Push this code to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Click "New app"
4. Select your repository
5. Deploy!

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
streamlit run app.py
