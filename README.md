This project is a web vulnerability scanner that utilizes the Wayback Machine to fetch historical URLs from a given domain and automatically scans them for common web vulnerabilities including:

✅ SQL Injection (SQLi)

✅ Cross-Site Scripting (XSS)

✅ Open Redirects

The application provides a Flask-based API with an interactive interface (via index.html) and leverages both asynchronous processing and multithreading for high-performance scanning.

🚀 Features
✅ Fetches historical URLs from Wayback Machine

✅ Scans URLs for:

SQL Injection vulnerabilities

XSS vulnerabilities using multiple payloads

Open Redirects

✅ Uses regex filters to clean up noisy URLs

✅ Optimized with:

aiohttp for async HTTP calls

ThreadPoolExecutor for parallel vulnerability scanning

✅ Flask REST API with simple frontend

✅ Colored terminal logging using colorama

✅ Progress bar with tqdm for better CLI visibility

📦 Tech Stack
Python 3.7+

Flask (Backend API)

aiohttp / asyncio

requests

concurrent.futures

tqdm / colorama

re / logging / aiofiles

Wayback Machine API

🖥️ Demo
Enter your target domain

Specify the number of historical URLs to analyze

Click Scan

Receive categorized lists of:

SQLi-vulnerable URLs

XSS-vulnerable URLs

Open redirect-vulnerable URLs

